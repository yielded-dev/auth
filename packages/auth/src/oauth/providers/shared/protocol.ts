import * as Discovery from "@yielded/oauth/Discovery";
import * as Grant from "@yielded/oauth/Grant";
import * as OAuth from "@yielded/oauth/OAuth";
import * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Signature from "effect/crypto/Signature";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as HttpClient from "effect/http/HttpClient";
import * as Jwks from "effect/jose/Jwks";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import { reportAuthDiagnostic, withoutObservability } from "../../../internal/diagnostics";
import { makeScopedOperation } from "../../../internal/scoped-operation";
import { timeoutOrElseWithCause } from "../../../internal/timeout";
import { RequestBindingFlowId } from "../../../operations/requestBindingModels";
import { selectCallback } from "../../callback";
import { OAuthProtocol } from "../../OAuthProtocol";
import { OAuthProviderKey } from "../../schema";
import { OAuthProtocolRejected, OAuthRejected, OAuthUnavailable } from "../../signInErrors";
import {
  OAuthAuthorizationPrompt,
  OAuthCallbackId,
  OAuthCodeResponse,
  OAuthDisplayProfile,
  OAuthLoginHint,
  OAuthNativeCallbackId,
  OAuthNativeCredential,
  type OAuthNativeName,
  OAuthNativeProtocolConfiguration,
  OAuthNativeProtocolPreparation,
  OAuthProtocolConfiguration,
  OAuthProtocolPreparation,
  OAuthTransactionSecrets,
  OAuthVerifiedExternalIdentity,
} from "../../signInModels";
import { makeOAuthSnapshot } from "../../signInSnapshot";
import { classifyOAuthError } from "./classifyOAuthError";
import { nativeAudiences, tokenCompatibility } from "./compatibility";
import { registrationKind, type InstalledConfiguration } from "./configuration";
import { discoveryProfile } from "./discovery";
import { authorizeWithCommaScopes } from "./http";
import {
  persistedResponseIssuerMode,
  type OpenIdConnectConfigurationError,
  type OpenIdConnectOidcProvider,
} from "./models";
import {
  decodeAppleCallbackUser,
  decodeOidcProfile,
  mergeAppleName,
  mergeUserInfo,
} from "./profile";
import { randomSecret } from "./randomSecret";
import { tokens } from "./receipt";
import { subjectInTenant } from "./tenantSubject";

const beginInput = Schema.Struct({
  provider: OAuthProviderKey,
  callbackId: Schema.optionalKey(OAuthCallbackId),
  flowId: RequestBindingFlowId,
  prompt: Schema.optionalKey(OAuthAuthorizationPrompt),
  loginHint: Schema.optionalKey(OAuthLoginHint),
});

const exchangeInput = Schema.toType(
  Schema.Struct({
    configuration: OAuthProtocolConfiguration,
    response: OAuthCodeResponse,
    secrets: OAuthTransactionSecrets,
    verificationStartedAt: Schema.DateTimeUtcFromMillis,
    requestedAt: Schema.optionalKey(Schema.DateTimeUtcFromMillis),
  }),
);

const nativeBeginInput = Schema.Struct({
  provider: OAuthProviderKey,
  flowId: RequestBindingFlowId,
});

const nativeVerifyInput = Schema.toType(
  Schema.Struct({
    configuration: OAuthNativeProtocolConfiguration,
    credential: OAuthNativeCredential,
    secrets: OAuthTransactionSecrets,
    verificationStartedAt: Schema.DateTimeUtcFromMillis,
    requestedAt: Schema.optionalKey(Schema.DateTimeUtcFromMillis),
  }),
);

const plainIdentitySchema = Schema.Struct({
  subject: OAuthVerifiedExternalIdentity.fields.identity.fields.subject,
  profile: Schema.optionalKey(OAuthDisplayProfile),
});

const unavailable = () => OAuthUnavailable.make({});
const rejected = () => OAuthProtocolRejected.make({});

/** Project verified claims. Apple's unsigned first-consent name only fills missing names. */
const oidcIdentity = Effect.fnUntraced(function* (
  provider: OpenIdConnectOidcProvider,
  verified: Oidc.VerifiedIdToken,
  claims: Schema.JsonObject,
  name: OAuthNativeName | undefined,
) {
  const profile = yield* decodeOidcProfile(
    provider[discoveryProfile] === "apple" ? mergeAppleName(claims, name) : claims,
    provider.profileSchema,
  );

  const decodedSubject =
    provider.decodeSubject === undefined
      ? verified.subject
      : yield* provider.decodeSubject(Redacted.value(verified.claims));

  const subject = yield* subjectInTenant(
    provider.issuer,
    Redacted.value(verified.claims),
    decodedSubject,
    provider[discoveryProfile] === "microsoft",
  );

  return yield* snapshotOAuthVerifiedExternalIdentity.effect({
    identity: { provider: provider.provider, issuer: provider.issuer, subject },
    ...(profile === undefined ? {} : { profile }),
    ...(verified.authenticatedAt === undefined
      ? {}
      : { upstreamAuthenticatedAt: verified.authenticatedAt }),
  });
});

export const makeOpenIdConnectOAuthProtocol = Effect.fn("makeOpenIdConnectOAuthProtocol")(
  // Capture one provider table; each generation retains its own receipt rules.
  function* <R, Setup>(
    installation: Effect.Effect<
      InstalledConfiguration<R>,
      OpenIdConnectConfigurationError | OAuthUnavailable,
      Setup
    >,
  ): Effect.fn.Return<
    OAuthProtocol["Service"],
    OpenIdConnectConfigurationError | OAuthUnavailable,
    R | Setup | (SecureRandom.SecureRandom | Digest.Digest) | Scope.Scope
  > {
    const context = (yield* Effect.context<R>()).pipe(withoutObservability);
    const crypto = yield* SecureRandom.SecureRandom;
    const digests = yield* Digest.Digest;
    // Own application decoding as well as the native client's individual requests.
    const run = yield* makeScopedOperation(unavailable);

    // Setup shares the protocol's containment for supplied platform services.
    const { installed, timeoutSeconds } = yield* installation;

    const prepareAuthorization: OAuthProtocol["Service"]["prepareAuthorization"] = Effect.fn(
      "OpenIdConnect.prepareAuthorization",
    )(function* (input) {
      const request = yield* Schema.decodeEffect(beginInput)(input).pipe(
        Effect.mapError(() => OAuthRejected.make({})),
      );

      const entry = installed.find(
        ({ provider }) =>
          provider.issuance === "active" &&
          provider.provider === request.provider &&
          registrationKind(provider) === "web",
      );

      const provider = entry?.provider;

      const callback =
        provider === undefined
          ? undefined
          : selectCallback(provider.provider, provider.callbacks, request.callbackId);

      if (
        entry === undefined ||
        entry.client === undefined ||
        provider === undefined ||
        callback === undefined
      )
        return yield* OAuthRejected.make({});

      const responseIssuerMode = persistedResponseIssuerMode(
        provider.responseIssuerMode,
        entry.metadata.authorization_response_iss_parameter_supported,
      );

      const baseAuthOptions = {
        redirectUri: callback.redirectUri,
        scopes: provider.scopes,
        pkce: provider.pkceS256,
        issuerIdentification: responseIssuerMode,
        ...(provider.authorizationParameters === undefined
          ? {}
          : { parameters: provider.authorizationParameters }),
        ...(provider.protocol === "oidc" && provider.maxAgeSeconds !== undefined
          ? { maxAge: `${provider.maxAgeSeconds} seconds` as const }
          : {}),
        ...(request.prompt === undefined ? {} : { prompt: request.prompt }),
        ...(request.loginHint === undefined ? {} : { loginHint: request.loginHint }),
        ...(provider.responseMode === undefined ? {} : { responseMode: provider.responseMode }),
      };

      const authorized = yield* (
        provider.protocol === "oidc"
          ? Oidc.authorize(baseAuthOptions)
          : provider.scopeSeparator === ","
            ? authorizeWithCommaScopes(baseAuthOptions)
            : OAuth.authorize(baseAuthOptions)
      ).pipe(
        Effect.provideService(OAuth.Client, entry.client),
        Effect.provideService(SecureRandom.SecureRandom, crypto),
        Effect.provideService(Digest.Digest, digests),
        Effect.catchCause((cause) =>
          Effect.failCause(
            Cause.map(cause, (error) =>
              classifyOAuthError(error, { operation: "authorization_code", phase: "preSend" }),
            ),
          ),
        ),
      );

      const result = {
        configuration: {
          provider: provider.provider,
          protocol: provider.protocol,
          configurationGeneration: provider.configurationGeneration,
          issuer: provider.issuer,
          responseIssuerMode,
          callbackId: callback.callbackId,
          redirectUri: callback.redirectUri,
        },
        authorizationUrl: authorized.url,
        secrets: {
          namespace: "effect-auth/oauth-transaction-secrets/v1" as const,
          state: authorized.transaction.state,
          ...(authorized.transaction.pkceVerifier === undefined
            ? {}
            : { pkceVerifier: authorized.transaction.pkceVerifier }),
          ...(authorized.transaction.nonce === undefined
            ? {}
            : { oidcNonce: authorized.transaction.nonce }),
        },
        ...(provider.responseMode === undefined ? {} : { responseMode: provider.responseMode }),
      };

      return yield* snapshotOAuthProtocolPreparation.effect(result);
    });

    const exchangeVerifiedIdentity: OAuthProtocol["Service"]["exchangeVerifiedIdentity"] =
      Effect.fn("OpenIdConnect.exchangeVerifiedIdentity")(function* (input) {
        const request = yield* snapshotExchangeInput.effect(input);
        const saved = request.configuration;

        const entry = installed.find(
          ({ provider }) =>
            provider.provider === saved.provider &&
            provider.configurationGeneration === saved.configurationGeneration &&
            registrationKind(provider) === "web",
        );

        if (entry === undefined || entry.client === undefined) return yield* unavailable();
        const provider = entry.provider;
        const client = entry.client;

        const callback = provider.callbacks.find(
          (candidate) => candidate.callbackId === saved.callbackId,
        );

        if (callback === undefined) return yield* unavailable();

        const responseIssuerMode = persistedResponseIssuerMode(
          provider.responseIssuerMode,
          entry.metadata.authorization_response_iss_parameter_supported,
        );

        if (
          provider.protocol !== saved.protocol ||
          provider.issuer !== saved.issuer ||
          responseIssuerMode !== saved.responseIssuerMode ||
          callback.redirectUri !== saved.redirectUri
        )
          return yield* unavailable();
        if (
          (provider.protocol === "oidc") !== (request.secrets.oidcNonce !== undefined) ||
          provider.pkceS256 !== (request.secrets.pkceVerifier !== undefined) ||
          Redacted.value(request.response.state) !== Redacted.value(request.secrets.state) ||
          (responseIssuerMode === "required"
            ? request.response.issuer !== provider.issuer
            : request.response.issuer !== undefined)
        )
          return yield* rejected();
        const startedAt = DateTime.toEpochMillis(request.verificationStartedAt);

        if (startedAt < 0 || startedAt > DateTime.toEpochMillis(yield* DateTime.now))
          return yield* rejected();

        const receipt = yield* (
          entry.jsonTokenSender !== undefined
            ? entry.jsonTokenSender.codeGrant({
                code: request.response.code,
                redirectUri: saved.redirectUri,
                ...(request.secrets.pkceVerifier === undefined
                  ? {}
                  : { pkceVerifier: request.secrets.pkceVerifier }),
                ...(provider.tokenParameters === undefined
                  ? {}
                  : { parameters: provider.tokenParameters }),
              })
            : client.exchangeRaw(
                Grant.fromTransaction(
                  request.response.code,
                  {
                    issuer: entry.metadata.issuer,
                    clientId: provider.clientId,
                    redirectUri: saved.redirectUri,
                    ...(request.secrets.pkceVerifier === undefined
                      ? {}
                      : { pkceVerifier: request.secrets.pkceVerifier }),
                  },
                  provider.tokenParameters === undefined
                    ? undefined
                    : { parameters: provider.tokenParameters },
                ),
              )
        ).pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(
              Cause.map(cause, (error) =>
                classifyOAuthError(error, { operation: "authorization_code", phase: "token" }),
              ),
            ),
          ),
        );

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
          const oidcNonce = request.secrets.oidcNonce;

          if (
            entry.verifier === undefined ||
            grant.idToken === undefined ||
            oidcNonce === undefined
          )
            return yield* unavailable();

          const verified = yield* entry.verifier
            .verify(grant.idToken, {
              nonce: oidcNonce,
              ...(request.requestedAt === undefined ? {} : { requestedAt: request.requestedAt }),
              ...(provider.maxAgeSeconds === undefined
                ? {}
                : { maxAge: `${provider.maxAgeSeconds} seconds` }),
              accessToken: grant.accessToken,
              code: request.response.code,
            })
            .pipe(
              Effect.catchCause((cause) =>
                Effect.failCause(
                  Cause.map(cause, (error) =>
                    classifyOAuthError(error, {
                      operation: "authorization_code",
                      phase: "idToken",
                    }),
                  ),
                ),
              ),
            );

          const claims =
            provider.userInfo === "merge"
              ? yield* (function* () {
                  if (entry.discovery === undefined || entry.http === undefined) {
                    return yield* unavailable();
                  }

                  const userInfo = yield* Oidc.fetchUserInfo({
                    accessToken: grant.accessToken,
                    expectedSubject: verified.subject,
                    timeout: timeoutSeconds * 1000,
                    maxResponseBytes: 1_048_576,
                  }).pipe(
                    Effect.provideService(Discovery.Discovery, entry.discovery),
                    Effect.provideService(HttpClient.HttpClient, entry.http),
                    Effect.catchCause((cause) =>
                      Effect.failCause(
                        Cause.map(cause, (error) =>
                          classifyOAuthError(error, {
                            operation: "authorization_code",
                            phase: "userInfo",
                          }),
                        ),
                      ),
                    ),
                  );

                  return mergeUserInfo(Redacted.value(userInfo), Redacted.value(verified.claims));
                })()
              : Redacted.value(verified.claims);

          return yield* oidcIdentity(
            provider,
            verified,
            claims,
            yield* decodeAppleCallbackUser(request.response.user),
          );
        }

        if (provider.protocol !== "oauth") return yield* unavailable();

        const body =
          provider.identitySource.from === "token"
            ? Redacted.value(receipt.body)
            : entry.fetchProfile === undefined
              ? yield* unavailable()
              : yield* entry.fetchProfile(grant.accessToken).pipe(
                  Effect.catchCause((cause) =>
                    Effect.failCause(
                      Cause.map(cause, (error) =>
                        classifyOAuthError(error, {
                          operation: "authorization_code",
                          phase: "userInfo",
                        }),
                      ),
                    ),
                  ),
                );

        const decoded = yield* Effect.suspend(() =>
          provider.identitySource.decodeIdentity(body),
        ).pipe(
          Effect.provideContext(context),
          Effect.catchCause((cause) =>
            Effect.failCause(
              Cause.map(cause, (error) =>
                Schema.is(OAuthProtocolRejected)(error) ? rejected() : unavailable(),
              ),
            ),
          ),
        );

        const enriched =
          entry.enrichIdentity === undefined
            ? decoded
            : yield* entry.enrichIdentity(decoded, grant.accessToken);

        const identity = yield* Schema.decodeEffect(plainIdentitySchema)(enriched).pipe(
          Effect.mapError(rejected),
        );

        return yield* snapshotOAuthVerifiedExternalIdentity.effect({
          identity: {
            provider: provider.provider,
            issuer: provider.issuer,
            subject: identity.subject,
          },
          ...(identity.profile === undefined ? {} : { profile: identity.profile }),
        });
      });

    const prepareNative: NonNullable<OAuthProtocol["Service"]["prepareNative"]> = Effect.fn(
      "OpenIdConnect.prepareNative",
    )(function* (input) {
      const request = yield* Schema.decodeEffect(nativeBeginInput)(input).pipe(
        Effect.mapError(() => OAuthRejected.make({})),
      );

      const entry = installed.find(
        ({ provider }) =>
          provider.issuance === "active" &&
          provider.provider === request.provider &&
          registrationKind(provider) === "native",
      );

      if (entry === undefined || entry.provider.protocol !== "oidc")
        return yield* OAuthRejected.make({});
      const provider = entry.provider;

      const random = randomSecret.pipe(Effect.provideService(SecureRandom.SecureRandom, crypto));

      // The state never leaves the sealed transaction, so no callback can present it.
      const state = yield* random;
      const nonce = yield* random;

      return yield* snapshotOAuthNativeProtocolPreparation.effect({
        configuration: {
          provider: provider.provider,
          protocol: provider.protocol,
          configurationGeneration: provider.configurationGeneration,
          issuer: provider.issuer,
          responseIssuerMode: "unsupported",
          callbackId: OAuthNativeCallbackId,
        },
        secrets: {
          namespace: "effect-auth/oauth-transaction-secrets/v1",
          state,
          oidcNonce: nonce,
        },
      });
    });

    const verifyNativeIdentity: NonNullable<OAuthProtocol["Service"]["verifyNativeIdentity"]> =
      Effect.fn("OpenIdConnect.verifyNativeIdentity")(function* (input) {
        const request = yield* snapshotNativeVerifyInput.effect(input);
        const saved = request.configuration;

        const entry = installed.find(
          ({ provider }) =>
            provider.provider === saved.provider &&
            provider.configurationGeneration === saved.configurationGeneration &&
            registrationKind(provider) === "native",
        );

        if (
          entry === undefined ||
          entry.nativeKeySet === undefined ||
          entry.provider.protocol !== "oidc" ||
          entry.provider.issuer !== saved.issuer ||
          saved.callbackId !== OAuthNativeCallbackId
        )
          return yield* unavailable();
        const provider = entry.provider;
        const nativeKeySet = entry.nativeKeySet;
        const nonce = request.secrets.oidcNonce;

        if (nonce === undefined || request.secrets.pkceVerifier !== undefined)
          return yield* rejected();
        const startedAt = DateTime.toEpochMillis(request.verificationStartedAt);

        if (startedAt < 0 || startedAt > DateTime.toEpochMillis(yield* DateTime.now))
          return yield* rejected();

        const alternativeClientIds = (provider[nativeAudiences] ?? []).filter(
          (audience) => audience !== provider.clientId,
        );

        // The platform token is the assertion. Its code only satisfies `c_hash`.
        const verified = yield* Oidc.verifyWithKeySet(request.credential.idToken, {
          issuer: entry.metadata.issuer,
          clientId: provider.clientId,
          ...(alternativeClientIds.length === 0 ? {} : { alternativeClientIds }),
          algorithms: nativeKeySet.algorithms,
          ...(nativeKeySet.issuerPolicy === undefined
            ? {}
            : { issuerPolicy: nativeKeySet.issuerPolicy }),
          nonce,
          ...(request.requestedAt === undefined ? {} : { requestedAt: request.requestedAt }),
          ...(request.credential.code === undefined
            ? {}
            : { code: request.credential.code, requireCodeHash: true }),
          ...(provider.maxAgeSeconds === undefined
            ? {}
            : { maxAge: `${provider.maxAgeSeconds} seconds` }),
        }).pipe(
          Effect.provideService(Jwks.Jwks, nativeKeySet.jwks),
          Effect.provideService(Signature.Signature, nativeKeySet.signature),
          Effect.provideService(Digest.Digest, nativeKeySet.digest),
          Effect.catchCause((cause) =>
            Effect.failCause(
              Cause.map(cause, (error) =>
                classifyOAuthError(error, { operation: "authorization_code", phase: "idToken" }),
              ),
            ),
          ),
        );

        if (
          Redacted.value(verified.claims).c_hash !== undefined &&
          request.credential.code === undefined
        ) {
          return yield* rejected();
        }

        return yield* oidcIdentity(
          provider,
          verified,
          Redacted.value(verified.claims),
          request.credential.name,
        );
      });

    return OAuthProtocol.of({
      prepareNative: (input) => run(prepareNative(input)),
      verifyNativeIdentity: (input) =>
        run(
          verifyNativeIdentity(input).pipe(
            timeoutOrElseWithCause({
              duration: timeoutSeconds * 1000,
              orElse: () => Effect.fail(unavailable()),
            }),
          ),
        ).pipe(
          Effect.tapError((error) =>
            reportAuthDiagnostic(
              "oauth-exchange",
              error._tag === "OAuthProtocolRejected" ? "rejected" : "unavailable",
            ),
          ),
        ),
      prepareAuthorization: (input) => run(prepareAuthorization(input)),
      exchangeVerifiedIdentity: (input) =>
        run(
          exchangeVerifiedIdentity(input).pipe(
            timeoutOrElseWithCause({
              duration: timeoutSeconds * 1000,
              orElse: () => Effect.fail(unavailable()),
            }),
          ),
        ).pipe(
          Effect.tapError((error) =>
            reportAuthDiagnostic(
              "oauth-exchange",
              error._tag === "OAuthProtocolRejected" ? "rejected" : "unavailable",
            ),
          ),
        ),
    });
  },
);

const snapshotOAuthProtocolPreparation = makeOAuthSnapshot(OAuthProtocolPreparation);
const snapshotExchangeInput = makeOAuthSnapshot(exchangeInput);
const snapshotOAuthVerifiedExternalIdentity = makeOAuthSnapshot(OAuthVerifiedExternalIdentity);
const snapshotOAuthNativeProtocolPreparation = makeOAuthSnapshot(OAuthNativeProtocolPreparation);
const snapshotNativeVerifyInput = makeOAuthSnapshot(nativeVerifyInput);
