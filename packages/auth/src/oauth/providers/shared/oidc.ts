import * as Discovery from "@yielded/oauth/Discovery";
import * as OAuth from "@yielded/oauth/OAuth";
import * as OAuthError from "@yielded/oauth/OAuthError";
import * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
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

import { reportAuthDiagnostic, reportAuthFailure } from "../../../internal/diagnostics";
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

const REGISTRATION_COOLDOWN_MILLIS = 30_000;

interface EntraPolicy {
  readonly signingKeyIssuerRequired: boolean;
  readonly expectedTenantId: string | undefined;
  readonly excludedTenantId: string | undefined;
  readonly caseInsensitiveTenantId: boolean;
}

interface SharedDiscoveryDocument {
  readonly metadata: Discovery.Metadata;
  readonly policy: EntraPolicy;
  readonly fetchedAt: number;
}

interface SharedDiscoveryHandle {
  readonly service: Discovery.Discovery["Service"];
  readonly resolve: (
    minFetchedAfter?: number,
  ) => Effect.Effect<SharedDiscoveryDocument, OAuthError.OAuthError>;
}

/** Shared lazy discovery cache within one installation (and across sign-in and
 * connected protocols in `OpenIdConnect.provider`). */
export type DiscoveryCache = Map<string, SharedDiscoveryHandle>;

export const makeDiscoveryCache = (): DiscoveryCache => new Map();

const discoveryFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.DiscoveryFailed({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const transportFailed = (description: string): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.TransportFailed({
      endpoint: "discovery",
      description,
    }),
  });

const asymmetricAlgorithmsOf = (
  advertised: ReadonlyArray<IdTokenSignedResponseAlg>,
): ReadonlyArray<Jwk.AsymmetricAlgorithm> =>
  advertised.filter(
    (algorithm): algorithm is Exclude<IdTokenSignedResponseAlg, "HS256"> => algorithm !== "HS256",
  );

const makeSharedDiscovery = Effect.fnUntraced(function* (options: {
  readonly issuer: string;
  readonly timeoutSeconds: number;
  readonly metadataUrl: string | undefined;
  readonly profile: typeof DiscoveryProfile.Type | undefined;
}) {
  const layerScope = yield* Effect.scope;
  const baseHttp = yield* HttpClient.HttpClient;
  const fetch = yield* FetchHttpClient.Fetch;
  const swapSemaphore = yield* Semaphore.make(1);
  const isMicrosoftProfile = options.profile === "microsoft";
  const reportedErrors = new WeakSet<object>();
  let closed = false;

  const reportOnce = Effect.fnUntraced(function* (error: OAuthError.OAuthError) {
    if (reportedErrors.has(error)) return;
    reportedErrors.add(error);

    if (error.reason._tag === "DiscoveryFailed") {
      yield* reportAuthDiagnostic("oauth-registration", "configuration");
      yield* reportAuthFailure("oauth-registration", Cause.fail(error));
    } else if (
      error.reason._tag === "TransportFailed" &&
      error.reason.description !== "Discovery is cooling down after a failed fetch" &&
      error.reason.description !== "The discovery scope is closed"
    ) {
      yield* reportAuthDiagnostic("oauth-registration", "unavailable");
    }
  });

  // Each attempt owns a single `Discovery.makeRemote` with infinite TTL, so it
  // succeeds at most once and its matched Entra policy and fetch timestamp stay
  // strictly paired with that single resolved document.
  const createAttempt = Effect.fnUntraced(function* () {
    const attemptScope = yield* Scope.fork(layerScope, "sequential");
    let matchedPolicy: EntraPolicy | undefined;
    let resolvedAt: number | undefined;

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

        matchedPolicy = {
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

        resolvedAt = yield* Clock.currentTimeMillis;

        return supplemented;
      }),
    }).pipe(
      Effect.provideService(Scope.Scope, attemptScope),
      Effect.provideService(HttpClient.HttpClient, baseHttp),
      Effect.provideService(FetchHttpClient.Fetch, fetch),
      Effect.onError(() => Scope.close(attemptScope, Exit.void).pipe(Effect.ignore)),
    );

    const resolveAttempt: Effect.Effect<SharedDiscoveryDocument, OAuthError.OAuthError> =
      remote.resolve.pipe(
        Effect.tapError(reportOnce),
        Effect.flatMap((metadata) => {
          if (matchedPolicy === undefined || resolvedAt === undefined) {
            return Effect.fail(discoveryFailed("Missing discovery issuer policy"));
          }

          return Effect.succeed({ metadata, policy: matchedPolicy, fetchedAt: resolvedAt });
        }),
      );

    return {
      scope: attemptScope,
      resolve: resolveAttempt,
      get fetchedAt() {
        return resolvedAt;
      },
    };
  });

  // Static URL/issuer validation runs at Layer build with zero network I/O.
  let current = yield* createAttempt().pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
    ),
  );

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      closed = true;
    }),
  );

  const resolve = (
    minFetchedAfter?: number,
  ): Effect.Effect<SharedDiscoveryDocument, OAuthError.OAuthError> =>
    Effect.suspend(() => {
      if (closed) return Effect.fail(transportFailed("The discovery scope is closed"));

      if (
        minFetchedAfter === undefined ||
        current.fetchedAt === undefined ||
        current.fetchedAt > minFetchedAfter
      ) {
        return current.resolve;
      }

      return swapSemaphore
        .withPermits(1)(
          Effect.uninterruptible(
            Effect.gen(function* () {
              if (closed) return yield* transportFailed("The discovery scope is closed");
              if (current.fetchedAt !== undefined && current.fetchedAt <= minFetchedAfter) {
                const next = yield* createAttempt();
                const previous = current;

                current = next;
                yield* Scope.close(previous.scope, Exit.void).pipe(Effect.ignore);
              }
            }),
          ),
        )
        .pipe(Effect.andThen(Effect.suspend(() => current.resolve)));
    });

  const service = Discovery.Discovery.of({
    resolve: Effect.map(resolve(), (document) => document.metadata),
  });

  return { service, resolve } satisfies SharedDiscoveryHandle;
});

const getSharedDiscovery = Effect.fnUntraced(function* (
  cache: DiscoveryCache,
  options: {
    readonly issuer: string;
    readonly timeoutSeconds: number;
    readonly metadataUrl: string | undefined;
    readonly profile: typeof DiscoveryProfile.Type | undefined;
  },
) {
  const key = JSON.stringify([
    options.issuer,
    options.timeoutSeconds,
    options.metadataUrl ?? "",
    options.profile ?? "",
  ]);

  const existing = cache.get(key);

  if (existing !== undefined) return existing;

  const created = yield* makeSharedDiscovery(options);

  cache.set(key, created);

  return created;
});

const makeLazyResolved = Effect.fnUntraced(function* <A>(
  discovery: SharedDiscoveryHandle,
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

  let rejected:
    | {
        readonly fetchedAt: number;
        readonly failedAt: number;
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

      const now = yield* Clock.currentTimeMillis;

      if (rejected !== undefined && now - rejected.failedAt < REGISTRATION_COOLDOWN_MILLIS) {
        return yield* OAuthUnavailable.make({});
      }

      const minFetchedAfter = rejected?.fetchedAt;

      const { metadata, policy, fetchedAt } = yield* discovery
        .resolve(minFetchedAfter)
        .pipe(
          Effect.mapError((error) =>
            classifyOAuthError(error, { operation: "authorization_code", phase: "preSend" }),
          ),
        );

      if (cached !== undefined && cached.metadata === metadata) {
        return cached.value;
      }

      return yield* semaphore.withPermits(1)(
        Effect.uninterruptibleMask((restore) =>
          Effect.gen(function* () {
            if (closed) return yield* OAuthUnavailable.make({});
            if (cached !== undefined && cached.metadata === metadata) {
              return cached.value;
            }

            const checkNow = yield* Clock.currentTimeMillis;

            if (
              rejected !== undefined &&
              rejected.fetchedAt === fetchedAt &&
              checkNow - rejected.failedAt < REGISTRATION_COOLDOWN_MILLIS
            ) {
              return yield* OAuthUnavailable.make({});
            }

            const childScope = yield* Scope.fork(layerScope, "sequential");

            const built = yield* Effect.exit(
              restore(build(metadata, policy).pipe(Effect.provideService(Scope.Scope, childScope))),
            );

            if (Exit.isFailure(built)) {
              yield* Scope.close(childScope, Exit.void).pipe(Effect.ignore);
              if (Cause.hasInterruptsOnly(built.cause)) {
                return yield* Effect.failCause(
                  Cause.map(built.cause, () => OAuthUnavailable.make({})),
                );
              }

              const finishedAt = yield* Clock.currentTimeMillis;

              rejected = { fetchedAt, failedAt: finishedAt };
              yield* reportAuthDiagnostic("oauth-registration", "configuration");
              yield* reportAuthFailure("oauth-registration", built.cause);

              return yield* OAuthUnavailable.make({});
            }

            if (closed) {
              yield* Scope.close(childScope, Exit.void).pipe(Effect.ignore);

              return yield* OAuthUnavailable.make({});
            }

            const previous = cached;

            rejected = undefined;
            cached = { metadata, value: built.value, scope: childScope };
            if (previous !== undefined) {
              yield* Scope.close(previous.scope, Exit.void).pipe(Effect.ignore);
            }

            return built.value;
          }),
        ),
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
  discoveryCache: DiscoveryCache = makeDiscoveryCache(),
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

    const sharedDiscovery = yield* getSharedDiscovery(discoveryCache, {
      issuer: provider.issuer,
      timeoutSeconds,
      metadataUrl: discoveryMetadataUrl(provider[discoveryProfile]),
      profile: provider[discoveryProfile],
    });

    if (isNative) {
      const { resolve } = yield* makeLazyResolved<ResolvedProvider<R>>(
        sharedDiscovery,
        Effect.fnUntraced(function* (metadata, policy) {
          const validated = yield* validateProviderMetadata(provider, metadata);

          const nativeKeySet = yield* makeNativeKeySet(validated, timeoutSeconds, {
            algorithms: provider.idTokenSignedResponseAlg,
            ...policy,
          }).pipe(
            Effect.provideService(HttpClient.HttpClient, baseHttp),
            Effect.provideService(FetchHttpClient.Fetch, fetch),
            Effect.provideService(Signature.Signature, signature),
            Effect.provideService(Digest.Digest, digest),
          );

          return { provider, metadata: validated, nativeKeySet };
        }),
      );

      installed.push({ provider, resolve });
      continue;
    }

    const client = yield* OAuth.make({
      clientId: provider.clientId,
      clientAuth,
      timeout: timeoutSeconds * 1000,
    }).pipe(
      Effect.provideService(Discovery.Discovery, sharedDiscovery.service),
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

    const { resolve } = yield* makeLazyResolved<ResolvedProvider<R>>(
      sharedDiscovery,
      Effect.fnUntraced(function* (metadata, policy) {
        const validated = yield* validateProviderMetadata(provider, metadata);

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

        const verifier = yield* makeVerifier(
          validated,
          sharedDiscovery.service,
          provider.clientId,
          timeoutSeconds,
          {
            algorithms: provider.idTokenSignedResponseAlg,
            ...policy,
            ...(hasStaticSecret(provider.authentication)
              ? { clientSecret: provider.authentication.secret }
              : {}),
          },
        ).pipe(
          Effect.provideService(HttpClient.HttpClient, baseHttp),
          Effect.provideService(FetchHttpClient.Fetch, fetch),
          Effect.provideService(Signature.Signature, signature),
          Effect.provideService(Digest.Digest, digest),
          Effect.provideService(Mac.Mac, mac),
        );

        return {
          provider,
          metadata: validated,
          client,
          discovery: sharedDiscovery.service,
          http: hardenedHttp,
          verifier,
        };
      }),
    );

    installed.push({ provider, resolve });
  }

  return { installed, timeoutSeconds };
});

export const installConnectedConfigurations = Effect.fn(
  "OpenIdConnect.installConnectedConfigurations",
)(function* <R>(
  input: OpenIdConnectConnectedProtocolOptions<R>,
  discoveryCache: DiscoveryCache = makeDiscoveryCache(),
) {
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

    const sharedDiscovery = yield* getSharedDiscovery(discoveryCache, {
      issuer: provider.issuer,
      timeoutSeconds,
      metadataUrl: discoveryMetadataUrl(provider[discoveryProfile]),
      profile: provider[discoveryProfile],
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
      Effect.provideService(Discovery.Discovery, sharedDiscovery.service),
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

    const { resolve } = yield* makeLazyResolved<ResolvedConnectedProvider<R>>(
      sharedDiscovery,
      Effect.fnUntraced(function* (metadata, policy) {
        const validated = yield* validateConnectedProviderMetadata(provider, metadata);

        const verifier = yield* makeVerifier(
          validated,
          sharedDiscovery.service,
          provider.clientId,
          timeoutSeconds,
          {
            algorithms: provider.idTokenSignedResponseAlg,
            ...policy,
            ...(hasStaticSecret(provider.authentication)
              ? { clientSecret: provider.authentication.secret }
              : {}),
          },
        ).pipe(
          Effect.provideService(HttpClient.HttpClient, baseHttp),
          Effect.provideService(FetchHttpClient.Fetch, fetch),
          Effect.provideService(Signature.Signature, signature),
          Effect.provideService(Digest.Digest, digest),
          Effect.provideService(Mac.Mac, mac),
        );

        return {
          provider,
          metadata: validated,
          client,
          discovery: sharedDiscovery.service,
          http: hardenedHttp,
          verifier,
        };
      }),
    );

    installed.push({ provider, resolve });
  }

  return { installed, timeoutSeconds };
});
