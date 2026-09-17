import { Crypto, DateTime, Effect, Encoding, Redacted, Schema } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";

import type { Provider } from "./app/application";
import {
  OAuthConnectedConfiguration,
  OAuthConnectedGrantResponse,
  OAuthConnectedProfile,
  OAuthConnectedTokenMaterial,
  OAuthPermissionProfileKey,
} from "./connectedModels";
import { OAuthProviderKey } from "./schema";
import { OAuthProtocolRejected, OAuthUnavailable, OAuthConfigurationError } from "./signInErrors";
import {
  OAuthCallbackId,
  OAuthIssuer,
  OAuthRedirectUri,
  OAuthTransactionSecrets,
} from "./signInModels";

export const Athlete = Schema.Struct({
  id: Schema.Int.check(Schema.isGreaterThan(0)),
  firstname: Schema.optionalKey(Schema.String),
  lastname: Schema.optionalKey(Schema.String),
  profile: Schema.optionalKey(Schema.String),
});

const Token = Schema.Struct({
  token_type: Schema.String.check(Schema.isPattern(/^[Bb]earer$/)),
  access_token: Schema.NonEmptyString.check(Schema.isMaxLength(16384)),
  refresh_token: Schema.NonEmptyString.check(Schema.isMaxLength(16384)),
  expires_at: Schema.Int.check(Schema.isGreaterThan(0)),
  athlete: Schema.optionalKey(Athlete),
  scope: Schema.optionalKey(Schema.String),
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

const key = OAuthProviderKey.make("strava");
const issuer = OAuthIssuer.make("https://www.strava.com");

/** Confidential Strava web authorization. Strava does not advertise S256 PKCE;
 * the managed application supplies a distinct, single-use browser binding.
 * Tokens are exchanged once through the supplied HttpClient (no retry middleware).
 * Retain this client registration while stored connections reference it.
 */
export const provider = (input: {
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly scopes: readonly [string, ...string[]];
}): Provider<OAuthConfigurationError, HttpClient.HttpClient | Crypto.Crypto> => {
  const options = { ...input, scopes: [...input.scopes] };

  return {
    configure: Effect.fn("Strava.configure")(function* (callbackUrl) {
      const scopes = yield* Schema.decodeUnknownEffect(Scopes)(options.scopes).pipe(
        Effect.mapError(() => OAuthConfigurationError.make({ reason: "policy" })),
      );

      if (!/^[0-9]+$/.test(options.clientId) || Redacted.value(options.clientSecret).length === 0)
        return yield* OAuthConfigurationError.make({ reason: "policy" });
      const http = (yield* HttpClient.HttpClient).pipe(HttpClient.withScope);
      const crypto = yield* Crypto.Crypto;

      const profile = OAuthConnectedProfile.make({
        key: OAuthPermissionProfileKey.make("strava"),
        generation: 1,
        issuance: "active",
        provider: key,
        clientRegistrationId: options.clientId,
        scopes,
        resources: [],
        retention: "access-and-refresh",
        maximumAccessLifetimeMillis: 6 * 60 * 60 * 1000,
        maximumRefreshLifetimeMillis: 30 * 24 * 60 * 60 * 1000,
        refreshAheadMillis: 60_000,
        refresh: "rotating",
        revocation: "unsupported",
      });

      const configuration = OAuthConnectedConfiguration.make({
        provider: key,
        protocol: "oauth",
        configurationGeneration: 1,
        issuer,
        responseIssuerMode: "unsupported",
        callbackId: OAuthCallbackId.make("strava"),
        redirectUri: OAuthRedirectUri.make(callbackUrl),
        profile,
      });

      const post = Effect.fn("Strava.token")(
        function* (parameters: Readonly<Record<string, string>>) {
          const response = yield* http.execute(
            HttpClientRequest.post("https://www.strava.com/oauth/token").pipe(
              HttpClientRequest.bodyUrlParams({
                client_id: options.clientId,
                client_secret: Redacted.value(options.clientSecret),
                ...parameters,
              }),
            ),
          );

          if (response.status === 400 || response.status === 401)
            return yield* OAuthProtocolRejected.make({});
          if (response.status !== 200) return yield* OAuthUnavailable.make({});

          return yield* HttpClientResponse.schemaBodyJson(Token)(response);
        },
        Effect.scoped,
        (effect) =>
          effect.pipe(
            Effect.catch((error) =>
              Effect.fail(
                error._tag === "OAuthProtocolRejected" ? error : OAuthUnavailable.make({}),
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
        profile,
        protocol: {
          prepareAuthorization: Effect.fn("Strava.prepareAuthorization")(function* (input) {
            if (
              input.callbackId !== configuration.callbackId ||
              JSON.stringify(input.profile) !== JSON.stringify(profile)
            )
              return yield* OAuthUnavailable.make({});

            const bytes = yield* crypto
              .randomBytes(32)
              .pipe(Effect.mapError(() => OAuthUnavailable.make({})));

            const state = Encoding.encodeBase64Url(bytes);

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

            const token = yield* post({
              grant_type: "authorization_code",
              code: Redacted.value(input.response.code),
            });

            const athlete = token.athlete;

            if (athlete === undefined) return yield* OAuthProtocolRejected.make({});

            // Prefer the token endpoint's authenticated receipt. Older Strava
            // responses report accepted scopes only on the bound callback.
            const granted = (token.scope ?? input.response.scope ?? "")
              .split(/[ ,]+/)
              .filter(Boolean);

            if (scopes.some((scope) => !granted.includes(scope)))
              return yield* OAuthProtocolRejected.make({});

            return OAuthConnectedGrantResponse.make({
              identity: { provider: key, issuer, subject: String(athlete.id) },
              profile: {
                displayName: [athlete.firstname, athlete.lastname].filter(Boolean).join(" "),
                ...(athlete.profile === undefined ? {} : { avatarUrl: athlete.profile }),
                providerData: { ...athlete },
              },
              scopes: granted,
              resources: [],
              accessExpiresAtMillis: token.expires_at * 1000,
              material: material(token),
            });
          }),
          refreshGrant: Effect.fn("Strava.refreshGrant")(function* (input) {
            yield* verifyConfiguration(input.context.configuration);
            if (input.material.refreshToken === undefined)
              return yield* OAuthProtocolRejected.make({});

            const token = yield* post({
              grant_type: "refresh_token",
              refresh_token: Redacted.value(input.material.refreshToken),
            });

            // Fetch identity again so a provider/account mismatch cannot silently
            // replace the grant held for this subject.
            const response = yield* http
              .execute(
                HttpClientRequest.get("https://www.strava.com/api/v3/athlete").pipe(
                  HttpClientRequest.bearerToken(Redacted.make(token.access_token)),
                ),
              )
              .pipe(Effect.mapError(() => OAuthUnavailable.make({})));

            if (response.status !== 200) return yield* OAuthUnavailable.make({});

            const athlete = yield* HttpClientResponse.schemaBodyJson(Athlete)(response).pipe(
              Effect.mapError(() => OAuthUnavailable.make({})),
            );

            if (
              String(athlete.id) !== input.context.identity.subject ||
              token.expires_at * 1000 <= DateTime.toEpochMillis(input.verificationStartedAt)
            )
              return yield* OAuthProtocolRejected.make({});

            return OAuthConnectedGrantResponse.make({
              identity: input.context.identity,
              scopes:
                token.scope === undefined
                  ? input.context.metadata.scopes
                  : token.scope.split(/[ ,]+/).filter(Boolean),
              resources: [],
              accessExpiresAtMillis: token.expires_at * 1000,
              material: material(token),
            });
          }, Effect.scoped),
          revokeGrant: () => Effect.fail(OAuthUnavailable.make({})),
        },
      };
    }),
  };
};
