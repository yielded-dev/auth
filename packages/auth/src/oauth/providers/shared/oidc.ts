import * as Discovery from "@yielded/oauth/Discovery";
import * as OAuth from "@yielded/oauth/OAuth";
import * as OAuthError from "@yielded/oauth/OAuthError";
import * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import * as Digest from "effect/crypto/Digest";
import * as Mac from "effect/crypto/Mac";
import * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Exit from "effect/Exit";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Jwks from "effect/jose/Jwks";
import * as Redacted from "effect/Redacted";
import * as Scope from "effect/Scope";
import * as Semaphore from "effect/Semaphore";

import { makeScopedOperation } from "../../../internal/scoped-operation";
import { OAuthUnavailable } from "../../signInErrors";
import {
  concreteEntraAuthority,
  isKnownEntraAuthority,
  isTenantIssuerTemplate,
} from "../microsoft/discovery";
import { makeEntraIssuerPolicy, makeEntraJwks } from "../microsoft/jwks";
import { classifyOAuthConfigurationError, classifyOAuthError } from "./classifyOAuthError";
import {
  installProvider,
  nativeAuthentication,
  prepareConfigurations,
  registrationKind,
  validateCallbackAuthorizationUrls,
  validateProviderMetadata,
  type InstalledProvider,
  type ResolvedProvider,
} from "./configuration";
import {
  installConnectedProvider,
  prepareConnectedConfigurations,
  validateConnectedProviderMetadata,
  type InstalledConnectedProvider,
  type ResolvedConnectedProvider,
} from "./connected/configuration";
import type { OpenIdConnectConnectedProtocolOptions } from "./connected/models";
import {
  discoveryMetadataUrl,
  discoveryProfile,
  matchEntraDiscoveryIssuer,
  supplementDiscovery,
  type DiscoveryProfile,
} from "./discovery";
import { captureHardenedHttp } from "./http";
import {
  advertisedIdTokenAlgorithms,
  hasStaticSecret,
  OpenIdConnectConfigurationError,
  type IdTokenSignedResponseAlg,
  type OpenIdConnectOAuthProtocolOptions,
} from "./models";
import type { NativeKeySet, Requirements as OAuthRequirements } from "./native";
import { PrivateKeyClientSecret } from "./privateKeyJwt";

export type Requirements = OAuthRequirements | Signature.Signature | Mac.Mac;

interface EntraPolicy {
  readonly signingKeyIssuerRequired: boolean;
  readonly expectedTenantId: string | undefined;
  readonly excludedTenantId: string | undefined;
  readonly caseInsensitiveTenantId: boolean;
}

const discoveryFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.DiscoveryFailed({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const asymmetricAlgorithmsOf = (
  advertised: ReadonlyArray<IdTokenSignedResponseAlg>,
): ReadonlyArray<Jwk.AsymmetricAlgorithm> =>
  advertised.filter(
    (algorithm): algorithm is Exclude<IdTokenSignedResponseAlg, "HS256"> => algorithm !== "HS256",
  );

const validateVerifierPolicy = Effect.fnUntraced(function* (
  metadata: Discovery.Metadata,
  policy: EntraPolicy,
  options: {
    readonly algorithms: ReadonlyArray<IdTokenSignedResponseAlg>;
    readonly native: boolean;
    readonly hasStaticSecret: boolean;
  },
) {
  const advertised = advertisedIdTokenAlgorithms(
    metadata.id_token_signing_alg_values_supported,
    options.algorithms,
  );

  if (advertised === undefined) {
    return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
  }

  if (options.native) {
    const algorithms = asymmetricAlgorithmsOf(advertised);

    if (algorithms.length === 0 || metadata.jwks_uri === undefined) {
      return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
    }

    return;
  }

  const hmacOnly = advertised.length === 1 && advertised[0] === "HS256";

  if (hmacOnly) {
    if (
      policy.signingKeyIssuerRequired ||
      policy.expectedTenantId !== undefined ||
      isTenantIssuerTemplate(metadata.issuer)
    ) {
      return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
    }
    if (!options.hasStaticSecret) {
      return yield* OpenIdConnectConfigurationError.make({ reason: "authentication" });
    }

    return;
  }

  if (metadata.jwks_uri === undefined) {
    return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
  }
});

const makeLazyOidcDiscovery = Effect.fnUntraced(function* (options: {
  readonly issuer: string;
  readonly timeoutSeconds: number;
  readonly metadataUrl: string | undefined;
  readonly profile: typeof DiscoveryProfile.Type | undefined;
  readonly validate: (
    metadata: Discovery.Metadata,
    policy: EntraPolicy,
  ) => Effect.Effect<void, OpenIdConnectConfigurationError | OAuthUnavailable>;
}) {
  const isMicrosoftProfile = options.profile === "microsoft";
  let inFlightPolicy: EntraPolicy | undefined;
  const policyByMetadata = new WeakMap<Discovery.Metadata, EntraPolicy>();

  const remote = yield* Discovery.makeRemote({
    issuer: options.issuer,
    timeout: options.timeoutSeconds * 1000,
    ...(options.metadataUrl === undefined ? {} : { url: options.metadataUrl }),
    issuerMatcher: (configuredIssuer, discoveredIssuer) => {
      const matched = matchEntraDiscoveryIssuer(
        configuredIssuer,
        discoveredIssuer,
        isMicrosoftProfile,
      );

      if (matched === undefined) {
        return Effect.fail(discoveryFailed("Discovered issuer does not match configured issuer"));
      }

      const concrete = concreteEntraAuthority(matched.issuer, isMicrosoftProfile);

      inFlightPolicy = {
        signingKeyIssuerRequired: matched.pinned || (concrete?.signingKeyIssuerRequired ?? false),
        expectedTenantId: matched.expectedTenantId ?? concrete?.tenantId,
        excludedTenantId: matched.excludedTenantId,
        caseInsensitiveTenantId: isKnownEntraAuthority(matched.issuer, isMicrosoftProfile),
      };

      return Effect.succeed(matched.issuer);
    },
    supplement: Effect.fnUntraced(function* (normalized) {
      const supplemented =
        options.profile === undefined
          ? normalized
          : yield* supplementDiscovery(normalized, options.profile).pipe(
              Effect.mapError((error) =>
                discoveryFailed("Discovered metadata failed provider profile validation", error),
              ),
            );

      const policy = inFlightPolicy;

      if (policy === undefined) {
        return yield* discoveryFailed("Missing discovery issuer policy");
      }

      yield* options
        .validate(supplemented, policy)
        .pipe(
          Effect.mapError((error) =>
            discoveryFailed("Discovered metadata failed provider capability validation", error),
          ),
        );

      return supplemented;
    }),
  }).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
    ),
  );

  const resolve: Effect.Effect<
    { readonly metadata: Discovery.Metadata; readonly policy: EntraPolicy },
    OAuthError.OAuthError
  > = Effect.flatMap(remote.resolve, (metadata) => {
    let policy = policyByMetadata.get(metadata);

    if (policy === undefined) {
      if (inFlightPolicy === undefined) {
        return Effect.fail(discoveryFailed("Missing discovery issuer policy"));
      }
      policy = inFlightPolicy;
      policyByMetadata.set(metadata, policy);
    }

    return Effect.succeed({ metadata, policy });
  });

  return { service: remote, resolve };
});

const makeLazyResolved = Effect.fnUntraced(function* <A>(
  resolveDiscovery: Effect.Effect<
    { readonly metadata: Discovery.Metadata; readonly policy: EntraPolicy },
    OAuthError.OAuthError
  >,
  build: (
    metadata: Discovery.Metadata,
    policy: EntraPolicy,
  ) => Effect.Effect<A, OpenIdConnectConfigurationError | OAuthUnavailable, Scope.Scope>,
) {
  const layerScope = yield* Effect.scope;
  const semaphore = yield* Semaphore.make(1);
  let closed = false;

  let cached:
    | {
        readonly metadata: Discovery.Metadata;
        readonly value: A;
        readonly scope: Scope.Closeable;
      }
    | undefined;

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      closed = true;
    }),
  );

  return {
    resolve: Effect.gen(function* () {
      if (closed) return yield* OAuthUnavailable.make({});

      const { metadata, policy } = yield* resolveDiscovery.pipe(
        Effect.mapError((error) =>
          classifyOAuthError(error, { operation: "authorization_code", phase: "preSend" }),
        ),
      );

      if (cached !== undefined && cached.metadata === metadata) {
        return cached.value;
      }

      return yield* semaphore.withPermits(1)(
        Effect.gen(function* () {
          if (closed) return yield* OAuthUnavailable.make({});
          if (cached !== undefined && cached.metadata === metadata) {
            return cached.value;
          }

          const childScope = yield* Scope.fork(layerScope, "sequential");

          const value = yield* build(metadata, policy).pipe(
            Effect.provideService(Scope.Scope, childScope),
            Effect.onError(() => Scope.close(childScope, Exit.void).pipe(Effect.ignore)),
            Effect.mapError(() => OAuthUnavailable.make({})),
          );

          if (closed) {
            yield* Scope.close(childScope, Exit.void).pipe(Effect.ignore);

            return yield* OAuthUnavailable.make({});
          }

          const previous = cached;

          cached = { metadata, value, scope: childScope };
          if (previous !== undefined) {
            yield* Scope.close(previous.scope, Exit.void).pipe(Effect.ignore);
          }

          return value;
        }),
      );
    }),
  };
});

const makeHmacVerifier = Effect.fn("OpenIdConnect.makeHmacVerifier")(function* (
  issuer: string,
  clientId: string,
  clientSecret: Redacted.Redacted<string>,
) {
  const mac = yield* Mac.Mac;
  const digest = yield* Digest.Digest;

  const secret = yield* Effect.try({
    try: () => Redacted.value(clientSecret),
    catch: () => OpenIdConnectConfigurationError.make({ reason: "authentication" }),
  });

  const jwkSecret = Redacted.make({
    kty: "oct" as const,
    alg: "HS256" as const,
    k: Base64Url.encode(new TextEncoder().encode(secret)),
  });

  const key = yield* Jwk.importSecret(jwkSecret, "HS256").pipe(
    Effect.ensuring(Effect.sync(() => Redacted.wipeUnsafe(jwkSecret))),
    Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "metadata" })),
  );

  const run = yield* makeScopedOperation(
    () =>
      new OAuthError.OAuthError({
        reason: new OAuthError.TransportFailed({
          endpoint: "jwks",
          description: "The verifier scope is closed",
        }),
      }),
  );

  return Oidc.Verifier.of({
    verify: (idToken, verifyOptions) =>
      run(
        Oidc.verify(idToken, key, {
          issuer,
          clientId,
          ...verifyOptions,
        }).pipe(Effect.provideService(Mac.Mac, mac), Effect.provideService(Digest.Digest, digest)),
      ),
  });
});

const makeVerifier = Effect.fn("OpenIdConnect.makeVerifier")(function* (
  metadata: Discovery.Metadata,
  discovery: Discovery.Discovery["Service"],
  clientId: string,
  timeoutSeconds: number,
  options: {
    readonly algorithms: ReadonlyArray<IdTokenSignedResponseAlg>;
    readonly signingKeyIssuerRequired: boolean;
    readonly expectedTenantId: string | undefined;
    readonly excludedTenantId: string | undefined;
    readonly caseInsensitiveTenantId: boolean;
    readonly clientSecret?: Redacted.Redacted<string>;
  },
) {
  const advertised = advertisedIdTokenAlgorithms(
    metadata.id_token_signing_alg_values_supported,
    options.algorithms,
  );

  if (advertised === undefined) {
    return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
  }

  const hmacOnly = advertised.length === 1 && advertised[0] === "HS256";

  if (hmacOnly) {
    if (
      options.signingKeyIssuerRequired ||
      options.expectedTenantId !== undefined ||
      isTenantIssuerTemplate(metadata.issuer)
    ) {
      return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
    }
    if (options.clientSecret === undefined) {
      return yield* OpenIdConnectConfigurationError.make({ reason: "authentication" });
    }

    return yield* makeHmacVerifier(metadata.issuer, clientId, options.clientSecret);
  }

  const algorithms = asymmetricAlgorithmsOf(advertised);

  if (metadata.jwks_uri === undefined) {
    return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
  }

  const entra = yield* makeEntraJwks({
    url: metadata.jwks_uri,
    timeoutMs: timeoutSeconds * 1000,
  }).pipe(
    Effect.mapError((error) =>
      error.reason._tag === "InvalidArgument"
        ? OpenIdConnectConfigurationError.make({ reason: "metadata" })
        : OAuthUnavailable.make({}),
    ),
  );

  const issuerPolicy = makeEntraIssuerPolicy({
    signingKeyIssuerRequired: options.signingKeyIssuerRequired,
    expectedTenantId: options.expectedTenantId,
    excludedTenantId: options.excludedTenantId,
    caseInsensitiveTenantId: options.caseInsensitiveTenantId,
    issuerOf: entra.issuerOf,
  });

  return yield* Oidc.makeVerifier({
    clientId,
    algorithms,
    issuerPolicy,
  }).pipe(
    Effect.provideService(Discovery.Discovery, discovery),
    Effect.provideService(Jwks.Jwks, entra.service),
    Effect.catchCause((cause) =>
      Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
    ),
  );
});

const makeNativeKeySet = Effect.fn("OpenIdConnect.makeNativeKeySet")(function* (
  metadata: Discovery.Metadata,
  timeoutSeconds: number,
  options: {
    readonly algorithms: ReadonlyArray<IdTokenSignedResponseAlg>;
    readonly signingKeyIssuerRequired: boolean;
    readonly expectedTenantId: string | undefined;
    readonly excludedTenantId: string | undefined;
    readonly caseInsensitiveTenantId: boolean;
  },
): Effect.fn.Return<
  NativeKeySet,
  OpenIdConnectConfigurationError | OAuthUnavailable,
  HttpClient.HttpClient | Signature.Signature | Digest.Digest | Scope.Scope
> {
  const advertised = advertisedIdTokenAlgorithms(
    metadata.id_token_signing_alg_values_supported,
    options.algorithms,
  );

  const algorithms = advertised === undefined ? [] : asymmetricAlgorithmsOf(advertised);

  if (algorithms.length === 0 || metadata.jwks_uri === undefined) {
    return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });
  }

  const signature = yield* Signature.Signature;
  const digest = yield* Digest.Digest;

  const entra = yield* makeEntraJwks({
    url: metadata.jwks_uri,
    timeoutMs: timeoutSeconds * 1000,
  }).pipe(
    Effect.mapError((error) =>
      error.reason._tag === "InvalidArgument"
        ? OpenIdConnectConfigurationError.make({ reason: "metadata" })
        : OAuthUnavailable.make({}),
    ),
  );

  return {
    jwks: entra.service,
    algorithms,
    issuerPolicy: makeEntraIssuerPolicy({
      signingKeyIssuerRequired: options.signingKeyIssuerRequired,
      expectedTenantId: options.expectedTenantId,
      excludedTenantId: options.excludedTenantId,
      caseInsensitiveTenantId: options.caseInsensitiveTenantId,
      issuerOf: entra.issuerOf,
    }),
    signature,
    digest,
  };
});

/** Only the OIDC adapter installs lazy remote discovery and signed ID-token verification. */
export const installConfigurations = Effect.fn("OpenIdConnect.installConfigurations")(function* <R>(
  input: OpenIdConnectOAuthProtocolOptions<R>,
) {
  const baseHttp = yield* HttpClient.HttpClient;
  const fetch = yield* FetchHttpClient.Fetch;
  const hardenedHttp = yield* captureHardenedHttp;
  const signature = yield* Signature.Signature;
  const digest = yield* Digest.Digest;
  const mac = yield* Mac.Mac;
  const clientSecrets = yield* PrivateKeyClientSecret;
  const { providers, timeoutSeconds } = yield* prepareConfigurations(input);
  const installed: InstalledProvider<R>[] = [];

  for (const provider of providers) {
    if (provider.protocol !== "oidc") {
      const resolved = yield* installProvider(
        provider,
        {
          issuer: provider.issuer,
          authorization_endpoint: provider.authorizationEndpoint,
          token_endpoint: provider.tokenEndpoint,
          response_types_supported: ["code"],
          ...(provider.pkceS256 ? { code_challenge_methods_supported: ["S256"] } : {}),
          authorization_response_iss_parameter_supported:
            provider.responseIssuerMode === "required",
        },
        timeoutSeconds,
      );

      installed.push({ provider, resolve: Effect.succeed(resolved) });
      continue;
    }

    const isNative = registrationKind(provider) === "native";
    const clientAuth = nativeAuthentication(provider.authentication, clientSecrets);

    const remoteDiscovery = yield* makeLazyOidcDiscovery({
      issuer: provider.issuer,
      timeoutSeconds,
      metadataUrl: discoveryMetadataUrl(provider[discoveryProfile]),
      profile: provider[discoveryProfile],
      validate: Effect.fnUntraced(function* (metadata, policy) {
        const validated = yield* validateProviderMetadata(provider, metadata);

        yield* validateVerifierPolicy(validated, policy, {
          algorithms: provider.idTokenSignedResponseAlg,
          native: isNative,
          hasStaticSecret: hasStaticSecret(provider.authentication),
        });

        if (!isNative) {
          yield* Effect.scoped(
            Effect.gen(function* () {
              const localDiscovery = yield* Discovery.makeLocal(validated).pipe(
                Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "metadata" })),
              );

              const tempClient = yield* OAuth.make({
                clientId: provider.clientId,
                clientAuth,
                timeout: timeoutSeconds * 1000,
              }).pipe(
                Effect.provideService(Discovery.Discovery, localDiscovery),
                Effect.provideService(HttpClient.HttpClient, baseHttp),
                Effect.provideService(FetchHttpClient.Fetch, fetch),
                Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "metadata" })),
              );

              yield* validateCallbackAuthorizationUrls(provider, tempClient);
            }),
          );
        }
      }),
    });

    if (isNative) {
      const { resolve } = yield* makeLazyResolved<ResolvedProvider<R>>(
        remoteDiscovery.resolve,
        (metadata, policy) =>
          makeNativeKeySet(metadata, timeoutSeconds, {
            algorithms: provider.idTokenSignedResponseAlg,
            ...policy,
          }).pipe(
            Effect.provideService(HttpClient.HttpClient, baseHttp),
            Effect.provideService(FetchHttpClient.Fetch, fetch),
            Effect.provideService(Signature.Signature, signature),
            Effect.provideService(Digest.Digest, digest),
            Effect.map((nativeKeySet) => ({ provider, metadata, nativeKeySet })),
          ),
      );

      installed.push({ provider, resolve });
      continue;
    }

    const client = yield* OAuth.make({
      clientId: provider.clientId,
      clientAuth,
      timeout: timeoutSeconds * 1000,
    }).pipe(
      Effect.provideService(Discovery.Discovery, remoteDiscovery.service),
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

    const { resolve } = yield* makeLazyResolved<ResolvedProvider<R>>(
      remoteDiscovery.resolve,
      (metadata, policy) =>
        makeVerifier(metadata, remoteDiscovery.service, provider.clientId, timeoutSeconds, {
          algorithms: provider.idTokenSignedResponseAlg,
          ...policy,
          ...(hasStaticSecret(provider.authentication)
            ? { clientSecret: provider.authentication.secret }
            : {}),
        }).pipe(
          Effect.provideService(HttpClient.HttpClient, baseHttp),
          Effect.provideService(FetchHttpClient.Fetch, fetch),
          Effect.provideService(Signature.Signature, signature),
          Effect.provideService(Digest.Digest, digest),
          Effect.provideService(Mac.Mac, mac),
          Effect.map((verifier) => ({
            provider,
            metadata,
            client,
            discovery: remoteDiscovery.service,
            http: hardenedHttp,
            verifier,
          })),
        ),
    );

    installed.push({ provider, resolve });
  }

  return { installed, timeoutSeconds };
});

export const installConnectedConfigurations = Effect.fn(
  "OpenIdConnect.installConnectedConfigurations",
)(function* <R>(input: OpenIdConnectConnectedProtocolOptions<R>) {
  const baseHttp = yield* HttpClient.HttpClient;
  const fetch = yield* FetchHttpClient.Fetch;
  const hardenedHttp = yield* captureHardenedHttp;
  const signature = yield* Signature.Signature;
  const digest = yield* Digest.Digest;
  const mac = yield* Mac.Mac;
  const clientSecrets = yield* PrivateKeyClientSecret;
  const { providers, timeoutSeconds } = yield* prepareConnectedConfigurations(input);
  const installed: InstalledConnectedProvider<R>[] = [];

  for (const provider of providers) {
    if (provider.protocol !== "oidc") {
      const resolved = yield* installConnectedProvider(
        provider,
        {
          issuer: provider.issuer,
          authorization_endpoint: provider.authorizationEndpoint,
          token_endpoint: provider.tokenEndpoint,
          response_types_supported: ["code"],
          ...(provider.pkceS256 ? { code_challenge_methods_supported: ["S256"] } : {}),
          authorization_response_iss_parameter_supported:
            provider.responseIssuerMode === "required",
          ...(provider.revocation.mode === "rfc7009"
            ? { revocation_endpoint: provider.revocation.endpoint }
            : {}),
        },
        timeoutSeconds,
      );

      installed.push({ provider, resolve: Effect.succeed(resolved) });
      continue;
    }

    const remoteDiscovery = yield* makeLazyOidcDiscovery({
      issuer: provider.issuer,
      timeoutSeconds,
      metadataUrl: undefined,
      profile: undefined,
      validate: Effect.fnUntraced(function* (metadata, policy) {
        const validated = yield* validateConnectedProviderMetadata(provider, metadata);

        yield* validateVerifierPolicy(validated, policy, {
          algorithms: provider.idTokenSignedResponseAlg,
          native: false,
          hasStaticSecret: hasStaticSecret(provider.authentication),
        });
      }),
    });

    const client = yield* OAuth.make({
      clientId: provider.clientId,
      clientAuth: nativeAuthentication(provider.authentication, clientSecrets),
      timeout: timeoutSeconds * 1000,
      ...(provider.revocation.mode === "rfc7009"
        ? {
            revocationAuth: nativeAuthentication(provider.revocation.authentication, clientSecrets),
          }
        : {}),
    }).pipe(
      Effect.provideService(Discovery.Discovery, remoteDiscovery.service),
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

    const { resolve } = yield* makeLazyResolved<ResolvedConnectedProvider<R>>(
      remoteDiscovery.resolve,
      (metadata, policy) =>
        makeVerifier(metadata, remoteDiscovery.service, provider.clientId, timeoutSeconds, {
          algorithms: provider.idTokenSignedResponseAlg,
          ...policy,
          ...(hasStaticSecret(provider.authentication)
            ? { clientSecret: provider.authentication.secret }
            : {}),
        }).pipe(
          Effect.provideService(HttpClient.HttpClient, baseHttp),
          Effect.provideService(FetchHttpClient.Fetch, fetch),
          Effect.provideService(Signature.Signature, signature),
          Effect.provideService(Digest.Digest, digest),
          Effect.provideService(Mac.Mac, mac),
          Effect.map((verifier) => ({
            provider,
            metadata,
            client,
            discovery: remoteDiscovery.service,
            http: hardenedHttp,
            verifier,
          })),
        ),
    );

    installed.push({ provider, resolve });
  }

  return { installed, timeoutSeconds };
});
