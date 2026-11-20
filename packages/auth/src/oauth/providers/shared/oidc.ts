import * as Discovery from "@yielded/oauth/Discovery";
import * as OAuthError from "@yielded/oauth/OAuthError";
import * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import * as Context from "effect/Context";
import * as Digest from "effect/crypto/Digest";
import * as Mac from "effect/crypto/Mac";
import * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Jwks from "effect/jose/Jwks";
import * as Redacted from "effect/Redacted";

import { makeScopedOperation } from "../../../internal/scoped-operation";
import { OAuthUnavailable } from "../../signInErrors";
import {
  concreteEntraAuthority,
  isKnownEntraAuthority,
  isTenantIssuerTemplate,
} from "../microsoft/discovery";
import { makeEntraIssuerPolicy, makeEntraJwks } from "../microsoft/jwks";
import { classifyOAuthConfigurationError } from "./classifyOAuthError";
import {
  installProvider,
  prepareConfigurations,
  registrationKind,
  type InstalledProvider,
} from "./configuration";
import {
  installConnectedProvider,
  prepareConnectedConfigurations,
  type InstalledConnectedProvider,
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

export type Requirements = OAuthRequirements | Signature.Signature | Mac.Mac;

export interface DiscoveredProviderMetadata {
  readonly metadata: Discovery.Metadata;
  /** Local policy flag set when discovery pinned a template or `consumers` issuer. */
  readonly signingKeyIssuerRequired: boolean;
  /** Pinned tenant GUID that signed `tid` must match when discovery pinned a tenant or `consumers`. */
  readonly expectedTenantId: string | undefined;
  /** Local tenant exclusion for the matched issuer template. */
  readonly excludedTenantId: string | undefined;
}

/** Inward discovery port. One initialization owns the successful responses;
 * exact discovery policy and effective transport identities stay independent. */
export class ProviderDiscovery extends Context.Service<
  ProviderDiscovery,
  {
    readonly discover: (
      issuer: string,
      timeoutSeconds: number,
      metadataUrl: string | undefined,
      profile?: typeof DiscoveryProfile.Type,
    ) => Effect.Effect<
      DiscoveredProviderMetadata,
      OpenIdConnectConfigurationError | OAuthUnavailable,
      HttpClient.HttpClient
    >;
  }
>()("effect-auth/oauth/providers/ProviderDiscovery") {
  /** Evaluate once at each initialization root, never at module or declaration scope. */
  static readonly make = Effect.sync(() => {
    const cache = new Map<
      string,
      {
        readonly client: HttpClient.HttpClient;
        readonly fetch: typeof globalThis.fetch;
        readonly discovered: DiscoveredProviderMetadata;
      }
    >();

    return ProviderDiscovery.of({
      discover: Effect.fnUntraced(function* (
        issuer: string,
        timeoutSeconds: number,
        metadataUrl: string | undefined,
        profile?: typeof DiscoveryProfile.Type,
      ) {
        const client = yield* HttpClient.HttpClient;
        const fetch = yield* FetchHttpClient.Fetch;
        // oxlint-disable-next-line no-restricted-properties -- Collision-free tuple of bounded, validated discovery configuration.
        const key = JSON.stringify([issuer, timeoutSeconds, metadataUrl ?? null, profile ?? null]);
        const found = cache.get(key);

        if (found?.client === client && found.fetch === fetch) return found.discovered;

        let pinned = false;
        let expectedTenantId: string | undefined;
        let excludedTenantId: string | undefined;

        const metadata = yield* Effect.scoped(
          Discovery.makeRemote({
            issuer,
            timeout: timeoutSeconds * 1000,
            ...(metadataUrl === undefined ? {} : { url: metadataUrl }),
            issuerMatcher: (configuredIssuer, discoveredIssuer) => {
              const matched = matchEntraDiscoveryIssuer(
                configuredIssuer,
                discoveredIssuer,
                profile === "microsoft",
              );

              if (matched === undefined) {
                return Effect.fail(
                  new OAuthError.OAuthError({
                    reason: new OAuthError.DiscoveryFailed({
                      description: "Discovered issuer does not match configured issuer",
                    }),
                  }),
                );
              }

              pinned = matched.pinned;
              expectedTenantId = matched.expectedTenantId;
              excludedTenantId = matched.excludedTenantId;

              return Effect.succeed(matched.issuer);
            },
            ...(profile === undefined
              ? {}
              : {
                  supplement: (normalized) =>
                    supplementDiscovery(normalized, profile).pipe(
                      Effect.mapError(
                        () =>
                          new OAuthError.OAuthError({
                            reason: new OAuthError.DiscoveryFailed({
                              description: "Discovered metadata failed provider profile validation",
                            }),
                          }),
                      ),
                    ),
                }),
          }).pipe(Effect.flatMap((service) => service.resolve)),
        ).pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
          ),
        );

        const discovered: DiscoveredProviderMetadata = {
          metadata,
          signingKeyIssuerRequired: pinned,
          expectedTenantId,
          excludedTenantId,
        };

        cache.set(key, { client, fetch, discovered });

        return discovered;
      }),
    });
  });
}

const asymmetricAlgorithmsOf = (
  advertised: ReadonlyArray<IdTokenSignedResponseAlg>,
): ReadonlyArray<Jwk.AsymmetricAlgorithm> =>
  advertised.filter(
    (algorithm): algorithm is Exclude<IdTokenSignedResponseAlg, "HS256"> => algorithm !== "HS256",
  );

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
  HttpClient.HttpClient | Signature.Signature | Digest.Digest | OAuthRequirements
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

/** Only the OIDC adapter installs discovery and signed ID-token verification. */
export const installConfigurations = Effect.fn("OpenIdConnect.installConfigurations")(function* <R>(
  input: OpenIdConnectOAuthProtocolOptions<R>,
) {
  const discovery = yield* ProviderDiscovery;
  const http = yield* captureHardenedHttp;
  const { providers, timeoutSeconds } = yield* prepareConfigurations(input);
  const installed: InstalledProvider<R>[] = [];

  for (const provider of providers) {
    let raw: Discovery.Metadata;
    let signingKeyIssuerRequired = false;
    let expectedTenantId: string | undefined;
    let excludedTenantId: string | undefined;
    let caseInsensitiveTenantId = false;

    if (provider.protocol === "oidc") {
      const discovered = yield* discovery.discover(
        provider.issuer,
        timeoutSeconds,
        discoveryMetadataUrl(provider[discoveryProfile]),
        provider[discoveryProfile],
      );

      const isMicrosoftProfile = provider[discoveryProfile] === "microsoft";
      const concrete = concreteEntraAuthority(discovered.metadata.issuer, isMicrosoftProfile);

      raw = discovered.metadata;
      signingKeyIssuerRequired =
        discovered.signingKeyIssuerRequired || (concrete?.signingKeyIssuerRequired ?? false);
      expectedTenantId = discovered.expectedTenantId ?? concrete?.tenantId;
      excludedTenantId = discovered.excludedTenantId;
      caseInsensitiveTenantId = isKnownEntraAuthority(
        discovered.metadata.issuer,
        isMicrosoftProfile,
      );
    } else {
      raw = {
        issuer: provider.issuer,
        authorization_endpoint: provider.authorizationEndpoint,
        token_endpoint: provider.tokenEndpoint,
        response_types_supported: ["code"],
        ...(provider.pkceS256 ? { code_challenge_methods_supported: ["S256"] } : {}),
        authorization_response_iss_parameter_supported: provider.responseIssuerMode === "required",
      };
    }

    const entry = yield* installProvider(provider, raw, timeoutSeconds);

    if (provider.protocol !== "oidc") {
      installed.push(entry);
      continue;
    }

    if (registrationKind(provider) === "native") {
      installed.push({
        ...entry,
        nativeKeySet: yield* makeNativeKeySet(entry.metadata, timeoutSeconds, {
          algorithms: provider.idTokenSignedResponseAlg,
          signingKeyIssuerRequired,
          expectedTenantId,
          excludedTenantId,
          caseInsensitiveTenantId,
        }),
      });
      continue;
    }

    const localDiscovery = yield* Discovery.makeLocal(entry.metadata).pipe(
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

    installed.push({
      ...entry,
      discovery: localDiscovery,
      http,
      verifier: yield* makeVerifier(
        entry.metadata,
        localDiscovery,
        provider.clientId,
        timeoutSeconds,
        {
          algorithms: provider.idTokenSignedResponseAlg,
          signingKeyIssuerRequired,
          expectedTenantId,
          excludedTenantId,
          caseInsensitiveTenantId,
          ...(hasStaticSecret(provider.authentication)
            ? { clientSecret: provider.authentication.secret }
            : {}),
        },
      ),
    });
  }

  return { installed, timeoutSeconds };
});

export const installConnectedConfigurations = Effect.fn(
  "OpenIdConnect.installConnectedConfigurations",
)(function* <R>(input: OpenIdConnectConnectedProtocolOptions<R>) {
  const discovery = yield* ProviderDiscovery;
  const http = yield* captureHardenedHttp;
  const { providers, timeoutSeconds } = yield* prepareConnectedConfigurations(input);
  const installed: InstalledConnectedProvider<R>[] = [];

  for (const provider of providers) {
    let raw: Discovery.Metadata;
    let signingKeyIssuerRequired = false;
    let expectedTenantId: string | undefined;
    let excludedTenantId: string | undefined;
    let caseInsensitiveTenantId = false;

    if (provider.protocol === "oidc") {
      const discovered = yield* discovery.discover(
        provider.issuer,
        timeoutSeconds,
        undefined,
        undefined,
      );

      const isMicrosoftProfile = provider[discoveryProfile] === "microsoft";
      const concrete = concreteEntraAuthority(discovered.metadata.issuer, isMicrosoftProfile);

      raw = discovered.metadata;
      signingKeyIssuerRequired =
        discovered.signingKeyIssuerRequired || (concrete?.signingKeyIssuerRequired ?? false);
      expectedTenantId = discovered.expectedTenantId ?? concrete?.tenantId;
      excludedTenantId = discovered.excludedTenantId;
      caseInsensitiveTenantId = isKnownEntraAuthority(
        discovered.metadata.issuer,
        isMicrosoftProfile,
      );
    } else {
      raw = {
        issuer: provider.issuer,
        authorization_endpoint: provider.authorizationEndpoint,
        token_endpoint: provider.tokenEndpoint,
        response_types_supported: ["code"],
        ...(provider.pkceS256 ? { code_challenge_methods_supported: ["S256"] } : {}),
        authorization_response_iss_parameter_supported: provider.responseIssuerMode === "required",
        ...(provider.revocation.mode === "rfc7009"
          ? { revocation_endpoint: provider.revocation.endpoint }
          : {}),
      };
    }

    const entry = yield* installConnectedProvider(provider, raw, timeoutSeconds);

    if (provider.protocol !== "oidc") {
      installed.push(entry);
      continue;
    }

    const localDiscovery = yield* Discovery.makeLocal(entry.metadata).pipe(
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

    installed.push({
      ...entry,
      discovery: localDiscovery,
      http,
      verifier: yield* makeVerifier(
        entry.metadata,
        localDiscovery,
        provider.clientId,
        timeoutSeconds,
        {
          algorithms: provider.idTokenSignedResponseAlg,
          signingKeyIssuerRequired,
          expectedTenantId,
          excludedTenantId,
          caseInsensitiveTenantId,
          ...(hasStaticSecret(provider.authentication)
            ? { clientSecret: provider.authentication.secret }
            : {}),
        },
      ),
    });
  }

  return { installed, timeoutSeconds };
});
