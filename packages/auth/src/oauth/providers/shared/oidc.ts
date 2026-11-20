import * as Discovery from "@yielded/oauth/Discovery";
import type * as OAuth from "@yielded/oauth/OAuth";
import * as OAuthError from "@yielded/oauth/OAuthError";
import * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import * as Context from "effect/Context";
import * as Digest from "effect/crypto/Digest";
import * as Mac from "effect/crypto/Mac";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import type * as Redacted from "effect/Redacted";

import type { OAuthUnavailable } from "../../signInErrors";
import { classifyOAuthConfigurationError } from "./classifyOAuthError";
import { nativeAudiences } from "./compatibility";
import { installProvider, prepareConfigurations, type InstalledProvider } from "./configuration";
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
import {
  hasStaticSecret,
  type OpenIdConnectConfigurationError,
  type OpenIdConnectOAuthProtocolOptions,
} from "./models";
import type { Requirements as OAuthRequirements } from "./native";

export type Requirements = OAuthRequirements | Signature.Signature | Mac.Mac;

export interface DiscoveredProviderMetadata {
  readonly metadata: Discovery.Metadata;
  /** Local policy flag set when discovery pinned a template or `consumers` issuer. */
  readonly signingKeyIssuerRequired: boolean;
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
        let excludedTenantId: string | undefined;

        const metadata = yield* Effect.scoped(
          Discovery.makeRemote({
            issuer,
            timeout: timeoutSeconds * 1000,
            ...(metadataUrl === undefined ? {} : { url: metadataUrl }),
            issuerMatcher: (configuredIssuer, discoveredIssuer) => {
              const matched = matchEntraDiscoveryIssuer(configuredIssuer, discoveredIssuer);

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
          excludedTenantId,
        };

        cache.set(key, { client, fetch, discovered });

        return discovered;
      }),
    });
  });
}

const makeVerifier = Effect.fn("OpenIdConnect.makeVerifier")(function* (
  metadata: OAuth.Metadata,
  clientId: string,
  timeoutSeconds: number,
  options: {
    readonly algorithms: ReadonlyArray<Oidc.IdTokenAlgorithm>;
    readonly pkceS256: boolean;
    readonly excludedTenantId: string | undefined;
    readonly clientSecret?: Redacted.Redacted<string>;
    readonly audiences?: ReadonlyArray<string>;
  },
) {
  const context = Context.make(SecureRandom.SecureRandom, yield* SecureRandom.SecureRandom).pipe(
    Context.add(Digest.Digest, yield* Digest.Digest),
    Context.add(Signature.Signature, yield* Signature.Signature),
    Context.add(Mac.Mac, yield* Mac.Mac),
  );

  const verifier = yield* Oidc.makeVerifier({
    metadata,
    clientId,
    timeoutMs: timeoutSeconds * 1000,
    algorithms: options.algorithms,
    pkceS256: options.pkceS256,
    excludedTenantId: options.excludedTenantId,
    ...(options.clientSecret === undefined ? {} : { clientSecret: options.clientSecret }),
    ...(options.audiences === undefined ? {} : { audiences: options.audiences }),
  }).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
    ),
  );

  return {
    verify: (token: Redacted.Redacted<string>, input: Oidc.VerificationInput) =>
      verifier.verify(token, input).pipe(Effect.provideContext(context)),
  };
});

/** Only the OIDC adapter installs discovery and signed ID-token verification. */
export const installConfigurations = Effect.fn("OpenIdConnect.installConfigurations")(function* <R>(
  input: OpenIdConnectOAuthProtocolOptions<R>,
) {
  const discovery = yield* ProviderDiscovery;
  const { providers, timeoutSeconds } = yield* prepareConfigurations(input);
  const installed: InstalledProvider<R>[] = [];

  for (const provider of providers) {
    let raw: Discovery.Metadata;
    let signingKeyIssuerRequired = false;
    let excludedTenantId: string | undefined;

    if (provider.protocol === "oidc") {
      const discovered = yield* discovery.discover(
        provider.issuer,
        timeoutSeconds,
        discoveryMetadataUrl(provider[discoveryProfile]),
        provider[discoveryProfile],
      );

      raw = discovered.metadata;
      signingKeyIssuerRequired = discovered.signingKeyIssuerRequired;
      excludedTenantId = discovered.excludedTenantId;
    } else {
      raw = {
        issuer: provider.issuer,
        authorization_endpoint: provider.authorizationEndpoint,
        token_endpoint: provider.tokenEndpoint,
        authorization_response_iss_parameter_supported: provider.responseIssuerMode === "required",
      };
    }

    const entry = yield* installProvider(provider, raw, timeoutSeconds);

    installed.push(
      provider.protocol === "oidc"
        ? {
            ...entry,
            verifier: yield* makeVerifier(
              signingKeyIssuerRequired
                ? { ...entry.metadata, signing_key_issuer_required: true }
                : entry.metadata,
              provider.clientId,
              timeoutSeconds,
              {
                algorithms: provider.idTokenSignedResponseAlg,
                pkceS256: provider.pkceS256,
                excludedTenantId,
                ...(hasStaticSecret(provider.authentication)
                  ? { clientSecret: provider.authentication.secret }
                  : {}),
                ...(provider[nativeAudiences] === undefined
                  ? {}
                  : { audiences: provider[nativeAudiences] }),
              },
            ),
          }
        : entry,
    );
  }

  return { installed, timeoutSeconds };
});

export const installConnectedConfigurations = Effect.fn(
  "OpenIdConnect.installConnectedConfigurations",
)(function* <R>(input: OpenIdConnectConnectedProtocolOptions<R>) {
  const discovery = yield* ProviderDiscovery;
  const { providers, timeoutSeconds } = yield* prepareConnectedConfigurations(input);
  const installed: InstalledConnectedProvider<R>[] = [];

  for (const provider of providers) {
    let raw: Discovery.Metadata;
    let signingKeyIssuerRequired = false;
    let excludedTenantId: string | undefined;

    if (provider.protocol === "oidc") {
      const discovered = yield* discovery.discover(
        provider.issuer,
        timeoutSeconds,
        undefined,
        undefined,
      );

      raw = discovered.metadata;
      signingKeyIssuerRequired = discovered.signingKeyIssuerRequired;
      excludedTenantId = discovered.excludedTenantId;
    } else {
      raw = {
        issuer: provider.issuer,
        authorization_endpoint: provider.authorizationEndpoint,
        token_endpoint: provider.tokenEndpoint,
        authorization_response_iss_parameter_supported: provider.responseIssuerMode === "required",
        ...(provider.revocation.mode === "rfc7009"
          ? { revocation_endpoint: provider.revocation.endpoint }
          : {}),
      };
    }

    const entry = yield* installConnectedProvider(provider, raw, timeoutSeconds);

    installed.push(
      provider.protocol === "oidc"
        ? {
            ...entry,
            verifier: yield* makeVerifier(
              signingKeyIssuerRequired
                ? { ...entry.metadata, signing_key_issuer_required: true }
                : entry.metadata,
              provider.clientId,
              timeoutSeconds,
              {
                algorithms: provider.idTokenSignedResponseAlg,
                pkceS256: provider.pkceS256,
                excludedTenantId,
                ...(hasStaticSecret(provider.authentication)
                  ? { clientSecret: provider.authentication.secret }
                  : {}),
              },
            ),
          }
        : entry,
    );
  }

  return { installed, timeoutSeconds };
});
