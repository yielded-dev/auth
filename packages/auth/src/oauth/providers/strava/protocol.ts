import * as ClientAuth from "@yielded/oauth/ClientAuth";
import * as Cause from "effect/Cause";
import type * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import type * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";

import {
  OAuthConnectedConfiguration,
  OAuthConnectedGrantResponse,
  OAuthConnectedTokenMaterial,
} from "../../connectedModels";
import type { OAuthConnectedProtocol } from "../../OAuthConnectedProtocol";
import type { OAuthConnectedProfile } from "../../permissionProfile";
import {
  OAuthProtocolRejected,
  OAuthUnavailable,
  OAuthConfigurationError,
} from "../../signInErrors";
import {
  type OAuthCallbackId,
  OAuthRedirectUri,
  OAuthTransactionSecrets,
} from "../../signInModels";
import {
  captureHardenedHttp,
  decodeJsonObjectBytes,
  invalidArgument,
  reveal,
  sendRequest,
} from "../shared/http";
import { issuer, providerKey, type ProviderOptions } from "./models";
import { Athlete } from "./profile";

const tokenEndpoint = "https://www.strava.com/oauth/token";
const tokenLimits = { timeoutMs: 10_000, maxResponseBytes: 1_048_576 } as const;
const maxTokenRequestBytes = 131_072;
const utf8Encoder = new TextEncoder();

const Token = Schema.Struct({
  token_type: Schema.String.check(Schema.isPattern(/^[Bb]earer$/)),
  access_token: Schema.NonEmptyString.check(Schema.isMaxLength(16384)),
  refresh_token: Schema.NonEmptyString.check(Schema.isMaxLength(16384)),
  expires_at: Schema.Int.check(Schema.isGreaterThan(0)),
  athlete: Schema.optionalKey(Athlete),
  scope: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16384))),
});

const decodeGrant = Schema.decodeEffect(Schema.toType(OAuthConnectedGrantResponse));

const stravaSuccessFields = [
  "access_token",
  "refresh_token",
  "id_token",
  "token_type",
  "scope",
  "expires_in",
  "expires_at",
  "athlete",
] as const;

const stravaErrorIndicators = ["error", "error_description", "error_uri", "errors"] as const;

const hasSuccessFields = (body: Readonly<Record<string, Schema.Json>>): boolean =>
  stravaSuccessFields.some((key) => Object.hasOwn(body, key));

const hasErrorIndicator = (body: Readonly<Record<string, Schema.Json>>): boolean =>
  stravaErrorIndicators.some((key) => Object.hasOwn(body, key));

const encodeFormRequest = Effect.fnUntraced(function* (prepared: ClientAuth.PreparedRequest) {
  const body = new URLSearchParams();

  for (const [key, value] of prepared.parameters) {
    body.append(key, value);
  }

  const encoded = body.toString();

  if (utf8Encoder.encode(encoded).length > maxTokenRequestBytes) {
    return yield* invalidArgument("Encoded token request body exceeds maximum size");
  }

  let request = HttpClientRequest.post(tokenEndpoint).pipe(HttpClientRequest.acceptJson);

  for (const [name, value] of Object.entries(prepared.headers)) {
    request = HttpClientRequest.setHeader(request, name, value);
  }

  return HttpClientRequest.bodyText(
    request,
    encoded,
    "application/x-www-form-urlencoded;charset=UTF-8",
  );
});

// Fetch's JSON accessor buffers unknown fields too. Bound the scoped stream before decoding.
const readBody = Effect.fnUntraced(function* (response: HttpClientResponse.HttpClientResponse) {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;

  const chunks = yield* response.stream.pipe(
    Stream.mapEffect(
      Effect.fnUntraced(function* (chunk) {
        size += chunk.length;
        if (size > 1_048_576) return yield* OAuthUnavailable.make({});

        return yield* Effect.try({
          try: () => decoder.decode(chunk, { stream: true }),
          catch: () => OAuthUnavailable.make({}),
        });
      }),
    ),
    Stream.runCollect,
    Effect.mapError(() => OAuthUnavailable.make({})),
  );

  return yield* Effect.try({
    try: () => chunks.join("") + decoder.decode(),
    catch: () => OAuthUnavailable.make({}),
  });
});

const Scopes = Schema.NonEmptyArray(
  Schema.Literals([
    "read",
    "read_all",
    "profile:read_all",
    "profile:write",
    "activity:read",
    "activity:read_all",
    "activity:write",
  ]),
);

/** Confidential Strava authorization. The shared sign-in workflow supplies
 * single-use state/browser binding; this provider does not advertise S256 PKCE. */
export const makeConnectedProtocol = Effect.fn("Strava.configure")(function* (
  options: ProviderOptions,
  profile: OAuthConnectedProfile,
  callback: {
    readonly callbackId: typeof OAuthCallbackId.Type;
    readonly redirectUri: typeof OAuthRedirectUri.Type;
  },
): Effect.fn.Return<
  OAuthConnectedProtocol["Service"],
  OAuthConfigurationError,
  HttpClient.HttpClient | (SecureRandom.SecureRandom | Digest.Digest)
> {
  const callbackUrl = callback.redirectUri;

  const scopes = yield* Schema.decodeUnknownEffect(Scopes)(profile.scopes).pipe(
    Effect.mapError(() => OAuthConfigurationError.make({ reason: "policy" })),
  );

  if (!/^[0-9]+$/.test(options.clientId) || Redacted.value(options.clientSecret).length === 0)
    return yield* OAuthConfigurationError.make({ reason: "policy" });

  const http = yield* captureHardenedHttp;
  const scopedHttp = http.pipe(HttpClient.withScope);
  const crypto = yield* SecureRandom.SecureRandom;

  if (profile.provider !== providerKey || profile.clientRegistrationId !== options.clientId)
    return yield* OAuthConfigurationError.make({ reason: "policy" });

  // Pass the caller's handle directly so wiping the registration secret blocks
  // dispatch with `OAuthUnavailable` before any HTTP request is sent.
  const clientAuth = ClientAuth.secretPost(options.clientSecret);

  const configuration = OAuthConnectedConfiguration.make({
    provider: providerKey,
    protocol: "oauth",
    configurationGeneration: 1,
    issuer,
    responseIssuerMode: "unsupported",
    callbackId: callback.callbackId,
    redirectUri: OAuthRedirectUri.make(callbackUrl),
    profile,
  });

  const post = Effect.fn("Strava.token")(
    function* (
      grantType: "authorization_code" | "refresh_token",
      credentialKey: "code" | "refresh_token",
      credential: Redacted.Redacted<string>,
    ) {
      const revealedCredential = yield* reveal(credential);

      if (
        typeof revealedCredential !== "string" ||
        revealedCredential.length === 0 ||
        revealedCredential.length > 16_384
      ) {
        return yield* OAuthUnavailable.make({});
      }

      // Preserve Strava's released field order (`client_id`, `client_secret`,
      // `grant_type`, `code`/`refresh_token`) while keeping credentials and
      // `grant_type` framework-owned via `ClientAuth.withPreparedRequest`.
      const request = yield* ClientAuth.withPreparedRequest(
        clientAuth,
        { clientId: options.clientId, endpoint: tokenEndpoint, issuer },
        [
          ["grant_type", grantType],
          [credentialKey, revealedCredential],
        ],
        encodeFormRequest,
        { forbidGrantType: true, authPosition: "prepend" },
      );

      const response = yield* sendRequest(http, request, tokenLimits, "token");

      if (response.status === 200) {
        const body = yield* decodeJsonObjectBytes(response.bytes, response.status, "token");

        if (hasErrorIndicator(body)) {
          return yield* OAuthUnavailable.make({});
        }

        // oxlint-disable-next-line no-restricted-properties -- Decode Strava's non-standard token receipt (expires_at + embedded athlete) from bounded JSON.
        return yield* Schema.decodeUnknownEffect(Token)(body).pipe(
          Effect.mapError(() => OAuthUnavailable.make({})),
        );
      }

      if (response.status === 400) {
        // Inspect bounded JSON bytes on 400 regardless of Content-Type so
        // contradictory receipts combining token fields with errors cannot
        // produce a definitive rejection.
        const decoded = yield* decodeJsonObjectBytes(response.bytes, response.status, "token").pipe(
          Effect.option,
        );

        if (decoded._tag === "Some" && hasSuccessFields(decoded.value)) {
          return yield* OAuthUnavailable.make({});
        }

        return yield* OAuthProtocolRejected.make({});
      }

      return yield* OAuthUnavailable.make({});
    },
    (effect) =>
      effect.pipe(
        Effect.catchCause((cause) =>
          Effect.failCause(
            Cause.map(cause, (error) =>
              error._tag === "OAuthProtocolRejected" ? error : OAuthUnavailable.make({}),
            ),
          ),
        ),
      ),
  );

  const verifyConfiguration = (input: OAuthConnectedConfiguration) =>
    JSON.stringify(input) === JSON.stringify(configuration)
      ? Effect.void
      : Effect.fail(OAuthUnavailable.make({}));

  const material = (token: typeof Token.Type) =>
    OAuthConnectedTokenMaterial.make({
      namespace: "effect-auth/oauth-connected-token-material/v1",
      accessToken: Redacted.make(token.access_token),
      refreshToken: Redacted.make(token.refresh_token),
      continuation: { _tag: "OAuth" },
    });

  return {
    prepareAuthorization: Effect.fn("Strava.prepareAuthorization")(function* (input) {
      if (
        input.callbackId !== configuration.callbackId ||
        JSON.stringify(input.profile) !== JSON.stringify(profile)
      )
        return yield* OAuthUnavailable.make({});

      const bytes = yield* crypto
        .randomBytes(32)
        .pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(Cause.map(cause, () => OAuthUnavailable.make({}))),
          ),
        );

      const state = Base64Url.encode(bytes);

      bytes.fill(0);
      const url = new URL("https://www.strava.com/oauth/authorize");

      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", callbackUrl);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("approval_prompt", "auto");
      url.searchParams.set("scope", scopes.join(","));
      url.searchParams.set("state", state);

      // The shared envelope has a verifier field; this provider does not send
      // it as PKCE and does not claim PKCE protection.
      return {
        configuration,
        authorizationUrl: Redacted.make(url.toString()),
        secrets: OAuthTransactionSecrets.make({
          namespace: "effect-auth/oauth-transaction-secrets/v1",
          state: Redacted.make(state),
          pkceVerifier: Redacted.make(state),
        }),
      };
    }),
    exchangeGrant: Effect.fn("Strava.exchangeGrant")(function* (input) {
      yield* verifyConfiguration(input.configuration);
      if (Redacted.value(input.secrets.state) !== Redacted.value(input.response.state))
        return yield* OAuthProtocolRejected.make({});

      const token = yield* post("authorization_code", "code", input.response.code);
      const athlete = token.athlete;

      if (athlete === undefined) return yield* OAuthProtocolRejected.make({});

      // Prefer the token endpoint's authenticated receipt. Older Strava
      // responses report accepted scopes only on the bound callback.
      const granted = (token.scope ?? input.response.scope ?? "").split(/[ ,]+/).filter(Boolean);

      if (scopes.some((scope) => !granted.includes(scope)))
        return yield* OAuthProtocolRejected.make({});

      return yield* decodeGrant({
        identity: { provider: providerKey, issuer, subject: String(athlete.id) },
        profile: {
          displayName: [athlete.firstname, athlete.lastname].filter(Boolean).join(" "),
          // Strava uses this relative placeholder when the athlete has no photo.
          ...(athlete.profile === undefined || athlete.profile === "avatar/athlete/large.png"
            ? {}
            : { avatarUrl: athlete.profile }),
          providerData: { ...athlete },
        },
        scopes: granted,
        resources: [],
        accessExpiresAtMillis: token.expires_at * 1000,
        material: material(token),
      }).pipe(Effect.mapError(() => OAuthUnavailable.make({})));
    }),
    refreshGrant: Effect.fn("Strava.refreshGrant")(function* (input) {
      yield* verifyConfiguration(input.context.configuration);
      if (input.material.refreshToken === undefined) return yield* OAuthProtocolRejected.make({});

      const token = yield* post("refresh_token", "refresh_token", input.material.refreshToken);

      // Fetch identity again so a provider/account mismatch cannot silently
      // replace the grant held for this subject.
      const response = yield* scopedHttp
        .execute(
          HttpClientRequest.get("https://www.strava.com/api/v3/athlete").pipe(
            HttpClientRequest.bearerToken(Redacted.make(token.access_token)),
          ),
        )
        .pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(Cause.map(cause, () => OAuthUnavailable.make({}))),
          ),
        );

      if (response.status !== 200) return yield* OAuthUnavailable.make({});

      const athlete = yield* readBody(response).pipe(
        Effect.flatMap(Schema.decodeEffect(Schema.fromJsonString(Athlete))),
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => OAuthUnavailable.make({}))),
        ),
      );

      if (
        String(athlete.id) !== input.context.identity.subject ||
        token.expires_at * 1000 <= DateTime.toEpochMillis(input.verificationStartedAt)
      )
        return yield* OAuthProtocolRejected.make({});

      return yield* decodeGrant({
        identity: input.context.identity,
        scopes:
          token.scope === undefined
            ? input.context.metadata.scopes
            : token.scope.split(/[ ,]+/).filter(Boolean),
        resources: [],
        accessExpiresAtMillis: token.expires_at * 1000,
        material: material(token),
      }).pipe(Effect.mapError(() => OAuthUnavailable.make({})));
    }, Effect.scoped),
    revokeGrant: () => Effect.fail(OAuthUnavailable.make({})),
  };
});
