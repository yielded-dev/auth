import * as Pkce from "@yielded/oauth/Pkce";
import { Cause, Crypto, DateTime, Effect, Redacted, Schema } from "effect";

import { reportAuthFailure } from "../../internal/diagnostics";
import { RequestBindingFlowId } from "../../operations/requestBindingModels";
import { selectCallback } from "../callback";
import { OAuthProtocol } from "../OAuthProtocol";
import { OAuthProviderKey } from "../schema";
import { OAuthProtocolRejected, OAuthRejected, OAuthUnavailable } from "../signInErrors";
import {
  OAuthCallbackId,
  OAuthCodeResponse,
  OAuthDisplayProfile,
  OAuthProtocolConfiguration,
  OAuthProtocolPreparation,
  OAuthTransactionSecrets,
  OAuthVerifiedExternalIdentity,
} from "../signInModels";
import { snapshotOAuth } from "../signInSnapshot";
import { tokenCompatibility } from "./compatibility";
import { installConfigurations } from "./configuration";
import {
  type OpenIdConnectConfigurationError,
  type OpenIdConnectOAuthProtocolOptions,
} from "./models";
import type { Requirements } from "./native";
import { decodeOidcProfile } from "./profile";
import { tokens } from "./receipt";

const beginInput = Schema.Struct({
  provider: OAuthProviderKey,
  callbackId: Schema.optionalKey(OAuthCallbackId),
  flowId: RequestBindingFlowId,
});

const exchangeInput = Schema.toType(
  Schema.Struct({
    configuration: OAuthProtocolConfiguration,
    response: OAuthCodeResponse,
    secrets: OAuthTransactionSecrets,
    verificationStartedAt: Schema.DateTimeUtcFromMillis,
  }),
);

const plainIdentitySchema = Schema.Struct({
  subject: OAuthVerifiedExternalIdentity.fields.identity.fields.subject,
  profile: Schema.optionalKey(OAuthDisplayProfile),
});

const unavailable = () => OAuthUnavailable.make({});
const rejected = () => OAuthProtocolRejected.make({});

// Final containment for application callbacks and supplied platform services.
// Expected validation failures are typed; defects never establish non-issuance.
const unavailableOnDefect = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(
    Effect.tapCause((cause) =>
      Cause.hasDies(cause) ? reportAuthFailure("oauth-protocol", cause) : Effect.void,
    ),
    Effect.catchCause((cause): Effect.Effect<never, E | OAuthUnavailable> => {
      if (Cause.hasInterrupts(cause)) return Effect.interrupt;
      if (Cause.hasDies(cause)) return Effect.fail(unavailable());

      return Effect.failCause(cause);
    }),
  );

export const makeOpenIdConnectOAuthProtocol = Effect.fn("makeOpenIdConnectOAuthProtocol")(
  // Capture one provider table; each generation retains its own receipt rules.
  function* <R = never>(
    options: OpenIdConnectOAuthProtocolOptions<R>,
  ): Effect.fn.Return<
    OAuthProtocol["Service"],
    OpenIdConnectConfigurationError | OAuthUnavailable,
    R | Requirements
  > {
    const context = yield* Effect.context<R>();
    const crypto = yield* Crypto.Crypto;
    const { installed, timeoutSeconds } = yield* installConfigurations(options);

    const prepareAuthorization: OAuthProtocol["Service"]["prepareAuthorization"] = Effect.fn(
      "OpenIdConnect.prepareAuthorization",
    )(function* (input) {
      const request = yield* Schema.decodeEffect(beginInput)(input).pipe(
        Effect.mapError(() => OAuthRejected.make({})),
      );

      const entry = installed.find(
        ({ provider }) => provider.issuance === "active" && provider.provider === request.provider,
      );

      const provider = entry?.provider;

      const callback =
        provider === undefined
          ? undefined
          : selectCallback(provider.provider, provider.callbacks, request.callbackId);

      if (entry === undefined || provider === undefined || callback === undefined)
        return yield* OAuthRejected.make({});

      const state = yield* Pkce.random().pipe(
        Effect.provideService(Crypto.Crypto, crypto),
        Effect.mapError(unavailable),
      );

      const pkce = yield* Pkce.make().pipe(
        Effect.provideService(Crypto.Crypto, crypto),
        Effect.mapError(unavailable),
      );

      const nonce =
        provider.protocol === "oidc"
          ? yield* Pkce.random().pipe(
              Effect.provideService(Crypto.Crypto, crypto),
              Effect.mapError(unavailable),
            )
          : undefined;

      const url = yield* entry.client
        .authorizationUrl({
          redirectUri: callback.redirectUri,
          scopes: provider.scopes,
          state,
          codeChallenge: pkce.challenge,
          ...(nonce === undefined ? {} : { nonce }),
          ...(provider.authorizationParameters === undefined
            ? {}
            : { parameters: provider.authorizationParameters }),
          ...(provider.protocol === "oidc" && provider.maxAgeSeconds !== undefined
            ? { maxAgeSeconds: provider.maxAgeSeconds }
            : {}),
        })
        .pipe(Effect.mapError(unavailable));

      const result = {
        configuration: {
          provider: provider.provider,
          protocol: provider.protocol,
          configurationGeneration: provider.configurationGeneration,
          issuer: provider.issuer,
          responseIssuerMode: provider.responseIssuerMode,
          callbackId: callback.callbackId,
          redirectUri: callback.redirectUri,
        },
        authorizationUrl: url,
        secrets: {
          namespace: "effect-auth/oauth-transaction-secrets/v1" as const,
          state,
          pkceVerifier: pkce.verifier,
          ...(nonce === undefined ? {} : { oidcNonce: nonce }),
        },
      };

      return yield* snapshotOAuth(OAuthProtocolPreparation, result);
    });

    const exchangeVerifiedIdentity: OAuthProtocol["Service"]["exchangeVerifiedIdentity"] =
      Effect.fn("OpenIdConnect.exchangeVerifiedIdentity")(function* (input) {
        const request = yield* snapshotOAuth(exchangeInput, input);
        const saved = request.configuration;

        const entry = installed.find(
          ({ provider }) =>
            provider.provider === saved.provider &&
            provider.configurationGeneration === saved.configurationGeneration,
        );

        if (entry === undefined) return yield* unavailable();
        const provider = entry.provider;

        const callback = provider.callbacks.find(
          (candidate) => candidate.callbackId === saved.callbackId,
        );

        if (
          provider.protocol !== saved.protocol ||
          provider.issuer !== saved.issuer ||
          provider.responseIssuerMode !== saved.responseIssuerMode ||
          callback?.redirectUri !== saved.redirectUri
        )
          return yield* unavailable();
        if (
          (provider.protocol === "oidc") !== (request.secrets.oidcNonce !== undefined) ||
          Redacted.value(request.response.state) !== Redacted.value(request.secrets.state) ||
          (provider.responseIssuerMode === "required"
            ? request.response.issuer !== provider.issuer
            : request.response.issuer !== undefined)
        )
          return yield* rejected();
        const startedAt = DateTime.toEpochMillis(request.verificationStartedAt);

        if (startedAt < 0 || startedAt > DateTime.toEpochMillis(yield* DateTime.now))
          return yield* rejected();

        const receipt = yield* entry.client
          .codeGrant({
            code: request.response.code,
            redirectUri: saved.redirectUri,
            pkceVerifier: request.secrets.pkceVerifier,
            ...(provider.tokenParameters === undefined
              ? {}
              : { parameters: provider.tokenParameters }),
          })
          .pipe(Effect.mapError(unavailable));

        const grant = yield* tokens(
          receipt,
          provider.protocol === "oauth" ? provider[tokenCompatibility] : undefined,
          {
            scopes: provider.scopes,
            refreshRequired: false,
            operation: "authorization_code",
          },
        );

        if (provider.protocol === "oidc") {
          if (entry.verifier === undefined || grant.idToken === undefined)
            return yield* unavailable();

          const verified = yield* entry.verifier
            .verify(grant.idToken, {
              verificationStartedAt: request.verificationStartedAt,
              nonce: request.secrets.oidcNonce!,
              maxAgeSeconds: provider.maxAgeSeconds,
              accessToken: grant.accessToken,
              code: request.response.code,
            })
            .pipe(
              Effect.mapError((error) =>
                error._tag === "OAuthRejected" ? rejected() : unavailable(),
              ),
            );

          const profile = yield* decodeOidcProfile(
            Redacted.value(verified.claims),
            provider.issuer,
          );

          return yield* snapshotOAuth(OAuthVerifiedExternalIdentity, {
            identity: {
              provider: provider.provider,
              issuer: provider.issuer,
              subject: verified.subject,
            },
            ...(profile === undefined ? {} : { profile }),
            ...(verified.upstreamAuthenticatedAt === undefined
              ? {}
              : { upstreamAuthenticatedAt: verified.upstreamAuthenticatedAt }),
          });
        }

        const body = yield* entry.client
          .fetchProfile(grant.accessToken)
          .pipe(Effect.mapError(unavailable));

        if (provider.protocol !== "oauth") return yield* unavailable();

        const decoded = yield* Effect.suspend(() =>
          provider.identitySource.decodeIdentity(body),
        ).pipe(
          Effect.provideContext(context),
          Effect.catchCause(
            (cause): Effect.Effect<never, OAuthProtocolRejected | OAuthUnavailable> => {
              if (Cause.hasInterrupts(cause))
                return reportAuthFailure("oauth-identity", cause).pipe(
                  Effect.andThen(Effect.interrupt),
                );
              if (
                cause.reasons.length === 1 &&
                cause.reasons[0]?._tag === "Fail" &&
                Schema.is(OAuthProtocolRejected)(cause.reasons[0].error)
              )
                return Effect.fail(rejected());

              return reportAuthFailure("oauth-identity", cause).pipe(
                Effect.andThen(Effect.fail(unavailable())),
              );
            },
          ),
        );

        const identity = yield* Schema.decodeEffect(plainIdentitySchema)(decoded).pipe(
          Effect.mapError(rejected),
        );

        return yield* snapshotOAuth(OAuthVerifiedExternalIdentity, {
          identity: {
            provider: provider.provider,
            issuer: provider.issuer,
            subject: identity.subject,
          },
          ...(identity.profile === undefined ? {} : { profile: identity.profile }),
        });
      });

    return OAuthProtocol.of({
      prepareAuthorization: (input) => unavailableOnDefect(prepareAuthorization(input)),
      exchangeVerifiedIdentity: (input) =>
        unavailableOnDefect(exchangeVerifiedIdentity(input)).pipe(
          Effect.timeoutOrElse({
            duration: timeoutSeconds * 1000,
            orElse: () => Effect.fail(unavailable()),
          }),
        ),
    });
  },
  unavailableOnDefect,
);
