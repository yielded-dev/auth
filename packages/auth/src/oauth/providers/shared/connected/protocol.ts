import * as Discovery from "@yielded/oauth/Discovery";
import * as Grant from "@yielded/oauth/Grant";
import * as OAuth from "@yielded/oauth/OAuth";
import * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as HttpClient from "effect/http/HttpClient";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import { reportAuthDiagnostic, withoutObservability } from "../../../../internal/diagnostics";
import { makeScopedOperation } from "../../../../internal/scoped-operation";
import { timeoutOrElseWithCause } from "../../../../internal/timeout";
import { RequestBindingFlowId } from "../../../../operations/requestBindingModels";
import * as M from "../../../connectedModels";
import { OAuthConnectedProtocol } from "../../../OAuthConnectedProtocol";
import { OAuthProtocolRejected, OAuthUnavailable } from "../../../signInErrors";
import {
  OAuthAuthorizationPrompt,
  OAuthCallbackId,
  OAuthCodeResponse,
  OAuthDisplayProfile,
  OAuthExternalIdentity,
  OAuthInstant,
  OAuthLoginHint,
  OAuthProtocolPreparation,
  OAuthTransactionSecrets,
} from "../../../signInModels";
import { makeOAuthSnapshot } from "../../../signInSnapshot";
import { isTenantIssuerTemplate } from "../../microsoft/discovery";
import { classifyOAuthError } from "../classifyOAuthError";
import { type ConnectedCompatibility } from "../compatibility";
import { discoveryProfile } from "../discovery";
import { authorizeWithCommaScopes, commaScopeRefreshGrant } from "../http";
import { persistedResponseIssuerMode, type OpenIdConnectConfigurationError } from "../models";
import { decodeOidcProfile, mergeUserInfo } from "../profile";
import { ProviderRevocation } from "../ProviderRevocation";
import { tokens } from "../receipt";
import { subjectInTenant } from "../tenantSubject";
import {
  sameConnectedProfile,
  type InstalledConnectedConfiguration,
  type ResolvedConnectedProvider,
} from "./configuration";

const unavailable = () => OAuthUnavailable.make({});
const rejected = () => OAuthProtocolRejected.make({});

const prepareInput = Schema.Struct({
  profile: M.OAuthConnectedProfile,
  callbackId: OAuthCallbackId,
  flowId: RequestBindingFlowId,
  prompt: Schema.optionalKey(OAuthAuthorizationPrompt),
  loginHint: Schema.optionalKey(OAuthLoginHint),
});

const prepareOutput = Schema.Struct({
  ...OAuthProtocolPreparation.fields,
  configuration: M.OAuthConnectedConfiguration,
});

const exchangeInput = Schema.toType(
  Schema.Struct({
    configuration: M.OAuthConnectedConfiguration,
    secrets: OAuthTransactionSecrets,
    response: OAuthCodeResponse,
    verificationStartedAt: Schema.DateTimeUtcFromMillis,
    requestedAt: Schema.optionalKey(Schema.DateTimeUtcFromMillis),
  }),
);

const refreshInput = Schema.toType(
  Schema.Struct({
    context: M.OAuthConnectedTokenContext,
    material: M.OAuthConnectedTokenMaterial,
    verificationStartedAt: Schema.DateTimeUtcFromMillis,
  }),
);

const revokeInput = Schema.Struct({
  context: M.OAuthConnectedTokenContext,
  material: M.OAuthConnectedTokenMaterial,
});

const identitySchema = Schema.Struct({
  subject: OAuthExternalIdentity.fields.subject,
  profile: Schema.optionalKey(OAuthDisplayProfile),
});

const rawMetadataSchema = Schema.Struct({
  expires_in: Schema.optionalKey(Schema.Finite.check(Schema.isGreaterThan(0))),
  scope: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16447))),
});

const rawRefreshExpiry = Schema.UndefinedOr(Schema.Finite.check(Schema.isGreaterThanOrEqualTo(0)));

interface GrantMetadata {
  readonly expiresIn?: number;
  readonly scope?: string;
  readonly refreshExpiresIn?: number;
}

const receiptMetadata = Effect.fnUntraced(function* <R>(
  entry: ResolvedConnectedProvider<R>,
  receipt: Grant.TokenReceipt,
): Effect.fn.Return<GrantMetadata, Schema.SchemaError> {
  const body = Redacted.value(receipt.body);

  const decoded = yield* Schema.decodeEffect(rawMetadataSchema)(body);

  let refreshExpiresIn: number | undefined;

  if (entry.provider.refreshExpiry !== "unreported") {
    refreshExpiresIn = yield* Schema.decodeUnknownEffect(rawRefreshExpiry)(
      body[entry.provider.refreshExpiry.field],
    );
    if (refreshExpiresIn === 0 && entry.provider.refreshExpiry.zero === "unreported")
      refreshExpiresIn = undefined;
  }

  return {
    ...(decoded.expires_in === undefined ? {} : { expiresIn: decoded.expires_in }),
    ...(decoded.scope === undefined ? {} : { scope: decoded.scope }),
    ...(refreshExpiresIn === undefined ? {} : { refreshExpiresIn }),
  };
}, Effect.mapError(unavailable));

const sameStrings = (left: ReadonlyArray<string>, right: ReadonlyArray<string>) =>
  left.length === right.length &&
  [...left].sort().every((value, index) => value === [...right].sort()[index]);

export const makeConnectedProtocolWithCompatibility = Effect.fn(
  "makeOpenIdConnectConnectedProtocol",
)(function* <R, Setup>(
  installation: Effect.Effect<
    InstalledConnectedConfiguration<R>,
    OpenIdConnectConfigurationError | OAuthUnavailable,
    Setup
  >,
  compatibility?: ConnectedCompatibility,
): Effect.fn.Return<
  OAuthConnectedProtocol["Service"],
  OpenIdConnectConfigurationError | OAuthUnavailable,
  R | Setup | ProviderRevocation | (SecureRandom.SecureRandom | Digest.Digest) | Scope.Scope
> {
  const decoderContext = (yield* Effect.context<R>()).pipe(withoutObservability);
  const crypto = yield* SecureRandom.SecureRandom;
  const digests = yield* Digest.Digest;
  const providerRevocation = yield* ProviderRevocation;
  // Provider-owned revocation bypasses the generic OAuth client's transport.
  // Own the entire operation, including provider callbacks, in this lifetime.
  const run = yield* makeScopedOperation(unavailable);

  // Setup shares the protocol's containment for supplied platform services.
  const { installed, timeoutSeconds } = yield* installation;

  const retained = Effect.fn("OpenIdConnectConnected.retained")(function* (
    saved: M.OAuthConnectedConfiguration,
  ) {
    const entry = installed.find(
      ({ provider }) =>
        provider.provider === saved.provider &&
        provider.configurationGeneration === saved.configurationGeneration,
    );

    const provider = entry?.provider;

    if (
      !entry ||
      !provider ||
      provider.protocol !== saved.protocol ||
      provider.issuer !== saved.issuer ||
      (provider.responseIssuerMode !== "discovered" &&
        provider.responseIssuerMode !== saved.responseIssuerMode) ||
      provider.clientRegistrationId !== saved.profile.clientRegistrationId ||
      !provider.profiles.some((profile) => sameConnectedProfile(profile, saved.profile)) ||
      provider.callbacks.find((callback) => callback.callbackId === saved.callbackId)
        ?.redirectUri !== saved.redirectUri
    )
      return yield* unavailable();

    const resolved = yield* entry.resolve;

    if (
      persistedResponseIssuerMode(
        provider.responseIssuerMode,
        resolved.metadata.authorization_response_iss_parameter_supported,
      ) !== saved.responseIssuerMode
    )
      return yield* unavailable();

    return resolved;
  });

  const checkedStart = Effect.fn("OpenIdConnectConnected.startedAt")(function* (
    start: DateTime.Utc,
  ) {
    const value = DateTime.toEpochMillis(start);

    if (
      !Number.isSafeInteger(value) ||
      value < 0 ||
      value > DateTime.toEpochMillis(yield* DateTime.now)
    )
      return yield* unavailable();

    return value;
  });

  const tokenMetadata = Effect.fn("OpenIdConnectConnected.tokenMetadata")(function* (
    profile: M.OAuthConnectedProfile,
    metadata: GrantMetadata,
    start: number,
    refreshRetained: boolean,
  ) {
    const scopes =
      compatibility !== undefined
        ? yield* compatibility.decodeScopes(metadata.scope, profile.scopes)
        : metadata.scope === undefined
          ? profile.scopes
          : yield* Schema.decodeEffect(M.OAuthConnectedScopes)(metadata.scope.split(" ")).pipe(
              Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))),
            );

    if (new Set(scopes).size !== scopes.length || !sameStrings(scopes, profile.scopes))
      return yield* unavailable();

    const accessExpiresAtMillis =
      metadata.expiresIn === undefined
        ? undefined
        : yield* Schema.decodeEffect(OAuthInstant)(
            Math.floor(start + metadata.expiresIn * 1000),
          ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

    const refreshExpiresAtMillis =
      !refreshRetained || metadata.refreshExpiresIn === undefined
        ? undefined
        : yield* Schema.decodeEffect(OAuthInstant)(
            Math.floor(start + metadata.refreshExpiresIn * 1000),
          ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

    const now = DateTime.toEpochMillis(yield* DateTime.now);

    if (
      (accessExpiresAtMillis !== undefined && accessExpiresAtMillis <= now) ||
      (refreshExpiresAtMillis !== undefined && refreshExpiresAtMillis <= now)
    )
      return yield* unavailable();

    return {
      scopes: [...scopes],
      resources: [...profile.resources],
      ...(accessExpiresAtMillis === undefined ? {} : { accessExpiresAtMillis }),
      ...(refreshExpiresAtMillis === undefined ? {} : { refreshExpiresAtMillis }),
    };
  });

  const oidcIdentity = Effect.fn("OpenIdConnectConnected.oidcIdentity")(function* (
    entry: ResolvedConnectedProvider<R>,
    verified: Oidc.VerifiedIdToken,
    originalNonce: Redacted.Redacted<string>,
    previous?: {
      readonly identity: typeof OAuthExternalIdentity.Type;
      readonly continuation: Extract<
        M.OAuthConnectedTokenMaterial["continuation"],
        { readonly _tag: "Oidc" }
      >;
    },
    claims?: unknown,
  ) {
    const provider = entry.provider;

    if (provider.protocol !== "oidc") return yield* unavailable();

    // Refresh keeps the stored identity. UserInfo-only required claims belong
    // to the initial exchange, not the refresh ID token.
    const profile =
      previous === undefined
        ? yield* decodeOidcProfile(
            claims ?? Redacted.value(verified.claims),
            provider.profileSchema,
          ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))))
        : undefined;

    const decodedSubject =
      provider.decodeSubject === undefined
        ? verified.subject
        : yield* provider
            .decodeSubject(Redacted.value(verified.claims))
            .pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

    const namespaced = yield* subjectInTenant(
      provider.issuer,
      Redacted.value(verified.claims),
      decodedSubject,
      provider[discoveryProfile] === "microsoft",
    ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

    if (
      previous !== undefined &&
      ((previous.continuation.issuer !== undefined &&
        previous.continuation.issuer !== verified.issuer) ||
        namespaced !== previous.identity.subject)
    )
      return yield* unavailable();

    const subject = previous === undefined ? namespaced : previous.identity.subject;

    return {
      identity: { provider: provider.provider, issuer: provider.issuer, subject },
      ...(profile === undefined ? {} : { profile }),
      continuation: previous?.continuation ?? {
        _tag: "Oidc" as const,
        clientId: provider.clientId,
        nonce: Redacted.make(Redacted.value(originalNonce)),
        subject: verified.subject,
        issuer: verified.issuer,
        audience: [...verified.audience],
        ...(verified.authTime === undefined ? {} : { authTime: verified.authTime }),
      },
    };
  });

  const decodeIdentity = Effect.fn("OpenIdConnectConnected.decodeIdentity")(function* (
    entry: ResolvedConnectedProvider<R>,
    body: unknown,
    accessToken?: Redacted.Redacted<string>,
  ) {
    if (entry.provider.protocol !== "oauth") return yield* unavailable();
    const decoder = entry.provider.identitySource.decodeIdentity;

    const result = yield* Effect.suspend(() => decoder(body)).pipe(
      Effect.provideContext(decoderContext),
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))),
    );

    const enriched =
      accessToken === undefined || entry.enrichIdentity === undefined
        ? result
        : yield* entry
            .enrichIdentity(result, accessToken)
            .pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

    const value = yield* Schema.decodeEffect(identitySchema)(enriched).pipe(
      Effect.mapError(unavailable),
    );

    return {
      identity: {
        provider: entry.provider.provider,
        issuer: entry.provider.issuer,
        subject: value.subject,
      },
      ...(value.profile === undefined ? {} : { profile: value.profile }),
      continuation: { _tag: "OAuth" as const },
    };
  });

  const prepareAuthorization: OAuthConnectedProtocol["Service"]["prepareAuthorization"] = Effect.fn(
    "OpenIdConnectConnected.prepareAuthorization",
  )(function* (input) {
    const request = yield* snapshotPrepareInput.effect(input);

    const entry = installed.find(
      ({ provider }) =>
        provider.provider === request.profile.provider &&
        provider.issuance === "active" &&
        provider.profiles.some(
          (profile) =>
            profile.issuance === "active" && sameConnectedProfile(profile, request.profile),
        ),
    );

    const callback = entry?.provider.callbacks.find(
      (value) => value.callbackId === request.callbackId,
    );

    if (!entry || !callback || request.profile.issuance !== "active") return yield* rejected();

    const resolved = yield* entry.resolve;

    const responseIssuerMode = persistedResponseIssuerMode(
      resolved.provider.responseIssuerMode,
      resolved.metadata.authorization_response_iss_parameter_supported,
    );

    const authOptions = {
      redirectUri: callback.redirectUri,
      scopes:
        compatibility?.authorizationScopes(
          request.profile.scopes,
          request.profile.retention === "access-and-refresh",
        ) ?? request.profile.scopes,
      pkce: resolved.provider.pkceS256,
      issuerIdentification: responseIssuerMode,
      ...(resolved.provider.authorizationParameters === undefined
        ? {}
        : { parameters: resolved.provider.authorizationParameters }),
      resources: request.profile.resources,
      ...(resolved.provider.protocol === "oidc" && resolved.provider.maxAgeSeconds !== undefined
        ? { maxAge: `${resolved.provider.maxAgeSeconds} seconds` as const }
        : {}),
      ...(request.prompt === undefined ? {} : { prompt: request.prompt }),
      ...(request.loginHint === undefined ? {} : { loginHint: request.loginHint }),
      ...(resolved.provider.responseMode === undefined
        ? {}
        : { responseMode: resolved.provider.responseMode }),
    };

    const authorized = yield* (
      resolved.provider.protocol === "oidc"
        ? Oidc.authorize(authOptions)
        : resolved.provider.scopeSeparator === ","
          ? authorizeWithCommaScopes(authOptions)
          : OAuth.authorize(authOptions)
    ).pipe(
      Effect.provideService(OAuth.Client, resolved.client),
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
        provider: entry.provider.provider,
        protocol: entry.provider.protocol,
        configurationGeneration: entry.provider.configurationGeneration,
        issuer: entry.provider.issuer,
        responseIssuerMode,
        callbackId: callback.callbackId,
        redirectUri: callback.redirectUri,
        profile: request.profile,
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
      ...(entry.provider.responseMode === undefined
        ? {}
        : { responseMode: entry.provider.responseMode }),
    };

    return yield* snapshotPrepareOutput.effect(result);
  });

  const exchangeGrant: OAuthConnectedProtocol["Service"]["exchangeGrant"] = Effect.fn(
    "OpenIdConnectConnected.exchangeGrant",
  )(function* (input) {
    const request = yield* snapshotExchangeInput.effect(input),
      saved = request.configuration;

    const entry = yield* retained(saved),
      provider = entry.provider;

    const responseIssuerMode = persistedResponseIssuerMode(
      provider.responseIssuerMode,
      entry.metadata.authorization_response_iss_parameter_supported,
    );

    if (
      (provider.protocol === "oidc") !== (request.secrets.oidcNonce !== undefined) ||
      provider.pkceS256 !== (request.secrets.pkceVerifier !== undefined) ||
      Redacted.value(request.response.state) !== Redacted.value(request.secrets.state) ||
      (responseIssuerMode === "required"
        ? request.response.issuer !== provider.issuer
        : request.response.issuer !== undefined)
    )
      return yield* rejected();
    const start = yield* checkedStart(request.verificationStartedAt);

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
            resources: saved.profile.resources,
          })
        : entry.client.exchangeRaw(
            Grant.fromTransaction(
              request.response.code,
              {
                issuer: entry.metadata.issuer,
                clientId: provider.clientId,
                redirectUri: saved.redirectUri,
                ...(request.secrets.pkceVerifier === undefined
                  ? {}
                  : { pkceVerifier: request.secrets.pkceVerifier }),
                resources: saved.profile.resources,
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

    const grant = yield* tokens(receipt, compatibility, {
      scopes: saved.profile.scopes,
      refreshRequired: saved.profile.retention === "access-and-refresh",
      operation: "authorization_code",
    });

    const rawMetadata = yield* receiptMetadata(entry, receipt);

    const identity = yield* provider.protocol === "oidc"
      ? Effect.gen(function* () {
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
              : undefined;

          return yield* oidcIdentity(entry, verified, oidcNonce, undefined, claims);
        })
      : provider.identitySource.from === "token"
        ? decodeIdentity(entry, Redacted.value(receipt.body), grant.accessToken)
        : entry.fetchProfile === undefined
          ? Effect.fail(unavailable())
          : entry.fetchProfile(grant.accessToken).pipe(
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
              Effect.flatMap((body) => decodeIdentity(entry, body, grant.accessToken)),
            );

    const refreshToken =
      saved.profile.retention === "access-and-refresh" ? grant.refreshToken : undefined;

    const metadata = yield* tokenMetadata(
      saved.profile,
      rawMetadata,
      start,
      refreshToken !== undefined,
    );

    return yield* snapshotOAuthConnectedGrantResponse.effect({
      ...identity,
      ...metadata,
      material: {
        namespace: "effect-auth/oauth-connected-token-material/v1",
        accessToken: grant.accessToken,
        ...(refreshToken === undefined ? {} : { refreshToken: refreshToken }),
        continuation: identity.continuation,
      },
    });
  });

  const refreshGrant: OAuthConnectedProtocol["Service"]["refreshGrant"] = Effect.fn(
    "OpenIdConnectConnected.refreshGrant",
  )(function* (input) {
    const request = yield* snapshotRefreshInput.effect(input),
      saved = request.context.configuration;

    const entry = yield* retained(saved),
      provider = entry.provider,
      previous = request.material.continuation;

    if (
      saved.profile.retention !== "access-and-refresh" ||
      saved.profile.refresh === "unsupported" ||
      !request.material.refreshToken ||
      request.context.identity.provider !== provider.provider ||
      request.context.identity.issuer !== provider.issuer ||
      (provider.protocol === "oidc"
        ? previous._tag !== "Oidc" ||
          previous.clientId !== provider.clientId ||
          previous.nonce === undefined
        : previous._tag !== "OAuth") ||
      !sameStrings(request.context.metadata.scopes, saved.profile.scopes) ||
      !sameStrings(request.context.metadata.resources, saved.profile.resources)
    )
      return yield* unavailable();
    const start = yield* checkedStart(request.verificationStartedAt);

    if (
      (request.context.metadata.refreshUseUntilMillis !== undefined &&
        request.context.metadata.refreshUseUntilMillis <= start) ||
      (request.context.metadata.refreshExpiresAtMillis !== undefined &&
        request.context.metadata.refreshExpiresAtMillis <= start)
    )
      return yield* unavailable();

    const refreshGrantOptions = {
      refreshToken: request.material.refreshToken,
      ...(compatibility?.includeRefreshScope === false ? {} : { scopes: saved.profile.scopes }),
      ...(provider.refreshParameters === undefined
        ? {}
        : { parameters: provider.refreshParameters }),
      resources: saved.profile.resources,
    };

    const receipt = yield* (
      entry.jsonTokenSender !== undefined
        ? entry.jsonTokenSender.refreshGrant(refreshGrantOptions)
        : provider.protocol === "oauth" && provider.scopeSeparator === ","
          ? Effect.flatMap(commaScopeRefreshGrant(refreshGrantOptions), entry.client.exchangeRaw)
          : entry.client.exchangeRaw(Grant.refreshToken(refreshGrantOptions))
    ).pipe(
      Effect.catchCause((cause) =>
        Effect.failCause(
          Cause.map(cause, (error) =>
            classifyOAuthError(error, { operation: "refresh_token", phase: "token" }),
          ),
        ),
      ),
    );

    const grant = yield* tokens(receipt, compatibility, {
      scopes: saved.profile.scopes,
      refreshRequired: true,
      operation: "refresh_token",
    });

    if (
      saved.profile.refresh === "rotating" &&
      (grant.refreshToken === undefined ||
        Redacted.value(grant.refreshToken) === Redacted.value(request.material.refreshToken))
    )
      return yield* unavailable();
    const rawMetadata = yield* receiptMetadata(entry, receipt);

    if (provider.protocol === "oidc") {
      if (previous._tag !== "Oidc" || !previous.nonce || entry.verifier === undefined)
        return yield* unavailable();
      if (grant.idToken !== undefined) {
        const previousIssuer =
          previous.issuer ??
          (isTenantIssuerTemplate(entry.metadata.issuer) ? undefined : entry.metadata.issuer);

        if (previousIssuer === undefined) return yield* unavailable();

        const previousAudience = previous.audience ?? [previous.clientId];

        const verified = yield* entry.verifier
          .verify(grant.idToken, {
            accessToken: grant.accessToken,
            previous: {
              subject: previous.subject ?? request.context.identity.subject,
              issuer: previousIssuer,
              audience: previousAudience,
              nonce: previous.nonce,
              ...(previous.authTime === undefined ? {} : { authTime: previous.authTime }),
            },
          })
          .pipe(
            Effect.catchCause((cause) =>
              Effect.failCause(
                Cause.map(cause, (error) =>
                  classifyOAuthError(error, { operation: "refresh_token", phase: "idToken" }),
                ),
              ),
            ),
          );

        yield* oidcIdentity(entry, verified, previous.nonce, {
          identity: request.context.identity,
          continuation: previous,
        });
      }
    } else if (provider.identitySource.from === "token") {
      const identity = yield* decodeIdentity(
        entry,
        Redacted.value(receipt.body),
        grant.accessToken,
      );

      if (identity.identity.subject !== request.context.identity.subject)
        return yield* unavailable();
    } else {
      if (entry.fetchProfile === undefined) return yield* unavailable();

      const body = yield* entry
        .fetchProfile(grant.accessToken)
        .pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(
              Cause.map(cause, (error) =>
                classifyOAuthError(error, { operation: "refresh_token", phase: "userInfo" }),
              ),
            ),
          ),
        );

      const identity = yield* decodeIdentity(entry, body);

      if (identity.identity.subject !== request.context.identity.subject)
        return yield* unavailable();
    }
    const metadata = yield* tokenMetadata(saved.profile, rawMetadata, start, true);
    const finishedAt = DateTime.toEpochMillis(yield* DateTime.now);

    if (
      (request.context.metadata.refreshUseUntilMillis !== undefined &&
        request.context.metadata.refreshUseUntilMillis <= finishedAt) ||
      (request.context.metadata.refreshExpiresAtMillis !== undefined &&
        request.context.metadata.refreshExpiresAtMillis <= finishedAt)
    )
      return yield* unavailable();

    return yield* snapshotOAuthConnectedGrantResponse.effect({
      identity: request.context.identity,
      ...metadata,
      material: {
        namespace: "effect-auth/oauth-connected-token-material/v1",
        accessToken: grant.accessToken,
        ...(grant.refreshToken === undefined ? {} : { refreshToken: grant.refreshToken }),
        continuation: previous,
      },
    });
  });

  const revokeGrant: OAuthConnectedProtocol["Service"]["revokeGrant"] = Effect.fn(
    "OpenIdConnectConnected.revokeGrant",
  )(function* (input) {
    const request = yield* snapshotRevokeInput.effect(input),
      saved = request.context.configuration;

    const entry = yield* retained(saved),
      revocation = entry.provider.revocation;

    if (
      saved.profile.revocation !== "provider" ||
      revocation.mode === "unsupported" ||
      (revocation.mode === "provider-cohort" && compatibility === undefined) ||
      (revocation.mode === "rfc7009" &&
        request.material.refreshToken !== undefined &&
        revocation.tokenTypes !== "access-and-refresh") ||
      request.context.identity.provider !== entry.provider.provider ||
      request.context.identity.issuer !== entry.provider.issuer ||
      (entry.provider.protocol === "oidc"
        ? request.material.continuation._tag !== "Oidc" ||
          request.material.continuation.clientId !== entry.provider.clientId
        : request.material.continuation._tag !== "OAuth")
    )
      return yield* unavailable();
    if (revocation.mode === "provider-cohort") {
      yield* providerRevocation.revoke({
        clientId: entry.provider.clientId,
        authentication: entry.provider.authentication,
        context: request.context,
        material: request.material,
      });

      return "Confirmed" as const;
    }
    if (revocation.mode !== "rfc7009") return yield* unavailable();

    if (request.material.refreshToken !== undefined) {
      yield* entry.client
        .revoke({
          token: request.material.refreshToken,
          tokenTypeHint: "refresh_token",
        })
        .pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(
              Cause.map(cause, (error) =>
                classifyOAuthError(error, { operation: "revocation", phase: "revocation" }),
              ),
            ),
          ),
        );
    }

    yield* entry.client
      .revoke({
        token: request.material.accessToken,
        tokenTypeHint: "access_token",
      })
      .pipe(
        Effect.catchCause((cause) =>
          Effect.failCause(
            Cause.map(cause, (error) =>
              classifyOAuthError(error, { operation: "revocation", phase: "revocation" }),
            ),
          ),
        ),
      );

    return "Confirmed" as const;
  });

  const ready: NonNullable<OAuthConnectedProtocol["Service"]["ready"]> = Effect.fn(
    "OpenIdConnectConnected.ready",
  )(function* (target) {
    if (target === undefined) {
      yield* Effect.forEach(installed, (entry) => entry.resolve, {
        concurrency: 4,
        discard: true,
      });

      return;
    }

    if ("protocol" in target) {
      const entry = installed.find(
        ({ provider }) =>
          provider.provider === target.provider &&
          provider.configurationGeneration === target.configurationGeneration,
      );

      const provider = entry?.provider;

      if (
        !entry ||
        !provider ||
        provider.protocol !== target.protocol ||
        provider.issuer !== target.issuer ||
        (provider.responseIssuerMode !== "discovered" &&
          provider.responseIssuerMode !== target.responseIssuerMode) ||
        provider.clientRegistrationId !== target.profile.clientRegistrationId ||
        !provider.profiles.some((profile) => sameConnectedProfile(profile, target.profile)) ||
        provider.callbacks.find((callback) => callback.callbackId === target.callbackId)
          ?.redirectUri !== target.redirectUri
      ) {
        return yield* unavailable();
      }

      const resolved = yield* entry.resolve;

      if (
        persistedResponseIssuerMode(
          provider.responseIssuerMode,
          resolved.metadata.authorization_response_iss_parameter_supported,
        ) !== target.responseIssuerMode
      ) {
        return yield* unavailable();
      }

      return;
    }

    const matching = installed.filter(
      ({ provider }) =>
        provider.provider === target.provider &&
        (target.configurationGeneration === undefined ||
          provider.configurationGeneration === target.configurationGeneration),
    );

    yield* Effect.forEach(matching, (entry) => entry.resolve, {
      concurrency: 4,
      discard: true,
    });
  });

  return OAuthConnectedProtocol.of({
    ready: (target) => run(ready(target)),
    prepareAuthorization: (input) => run(prepareAuthorization(input)),
    exchangeGrant: (input) =>
      run(exchangeGrant(input)).pipe(
        timeoutOrElseWithCause({
          duration: timeoutSeconds * 1000,
          orElse: () => Effect.fail(unavailable()),
        }),
        Effect.tapError((error) =>
          reportAuthDiagnostic(
            "oauth-exchange",
            error._tag === "OAuthProtocolRejected" ? "rejected" : "unavailable",
          ),
        ),
      ),
    refreshGrant: (input) =>
      run(refreshGrant(input)).pipe(
        timeoutOrElseWithCause({
          duration: timeoutSeconds * 1000,
          orElse: () => Effect.fail(unavailable()),
        }),
        Effect.tapError((error) =>
          reportAuthDiagnostic(
            "oauth-exchange",
            error._tag === "OAuthProtocolRejected" ? "rejected" : "unavailable",
          ),
        ),
      ),
    revokeGrant: (input) =>
      run(revokeGrant(input)).pipe(
        timeoutOrElseWithCause({
          duration: timeoutSeconds * 1000,
          orElse: () => Effect.fail(unavailable()),
        }),
      ),
  });
});

export const makeOpenIdConnectConnectedProtocol = <R, Setup>(
  installation: Effect.Effect<
    InstalledConnectedConfiguration<R>,
    OpenIdConnectConfigurationError | OAuthUnavailable,
    Setup
  >,
): Effect.Effect<
  OAuthConnectedProtocol["Service"],
  OpenIdConnectConfigurationError | OAuthUnavailable,
  R | Setup | (SecureRandom.SecureRandom | Digest.Digest) | Scope.Scope
> =>
  makeConnectedProtocolWithCompatibility(installation).pipe(
    Effect.provide(ProviderRevocation.layerUnsupported),
  );

const snapshotPrepareInput = makeOAuthSnapshot(prepareInput);
const snapshotPrepareOutput = makeOAuthSnapshot(prepareOutput);
const snapshotExchangeInput = makeOAuthSnapshot(exchangeInput);
const snapshotOAuthConnectedGrantResponse = makeOAuthSnapshot(M.OAuthConnectedGrantResponse);
const snapshotRefreshInput = makeOAuthSnapshot(refreshInput);
const snapshotRevokeInput = makeOAuthSnapshot(revokeInput);
