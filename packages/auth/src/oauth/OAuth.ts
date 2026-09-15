import {
  Context,
  Crypto,
  DateTime,
  Duration,
  Effect,
  Encoding,
  Layer,
  Option,
  Redacted,
  Schema,
} from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";

import { AuthTokenCodec } from "../AuthTokenCodec";
import { type AuthStoreError, AuthTokenError } from "../Errors";
import type { SubjectId } from "../Schema";
import {
  type OAuthGrantRejected,
  type UnknownOAuthProvider,
  InvalidOAuthState,
  OAuthAccessDenied,
  OAuthConnectionNotFound,
  OAuthProviderError,
  OAuthReauthorizationRequired,
} from "./errors";
import { OAuthConnectionStore } from "./OAuthConnectionStore";
import type { OAuthProvider, OAuthTokenGrant } from "./OAuthProvider";
import { OAuthProviders } from "./OAuthProviders";
import { OAuthStateStore } from "./OAuthStateStore";
import { OAuthPolicy } from "./policy";
import {
  type OAuthProviderKey,
  OAuthAuthorization,
  OAuthCallbackParams,
  OAuthConnection,
  OAuthState,
  OAuthTokens,
} from "./schema";

const stateTokenScope = "effect-auth/oauth-state-token";

// oxlint-disable-next-line no-restricted-properties -- Callback query parameters are untrusted input.
const decodeCallbackParams = Schema.decodeUnknownEffect(OAuthCallbackParams);

export interface BeginOAuthInput {
  readonly provider: OAuthProviderKey;
  /** The application subject initiating the link; the state is bound to it. */
  readonly subjectId: SubjectId;
  /** The callback URL registered with the provider for this application. */
  readonly redirectUri: string;
}

export interface CompleteOAuthInput {
  readonly provider: OAuthProviderKey;
  /** The subject of the *current* session; must match the one that began the flow. */
  readonly subjectId: SubjectId;
  /** Must equal the redirect URI the flow began with. */
  readonly redirectUri: string;
  /** The raw callback query parameters, validated internally. */
  readonly params: unknown;
}

export type CompleteOAuthError =
  | UnknownOAuthProvider
  | InvalidOAuthState
  | OAuthAccessDenied
  | OAuthProviderError
  | AuthStoreError
  | AuthTokenError;

/**
 * Provider-independent OAuth 2.0 authorization-code workflow for linking
 * provider accounts to application subjects. Providers contribute endpoints
 * and response mappings through `OAuthProviders`; every security-relevant
 * step — state issuance and single-use validation, subject and redirect-URI
 * binding, code exchange, token refresh, revocation — lives here so it cannot
 * vary per provider.
 */
export class OAuth extends Context.Service<
  OAuth,
  {
    /**
     * Issues a single-use, expiring `state` bound to the subject and redirect
     * URI, and returns the provider authorization URL to redirect the actor
     * to.
     */
    readonly begin: (
      input: BeginOAuthInput,
    ) => Effect.Effect<OAuthAuthorization, UnknownOAuthProvider | AuthStoreError | AuthTokenError>;
    /**
     * Validates the callback, consumes the state (single use, whatever the
     * outcome), exchanges the code, fetches and validates the provider
     * identity, and persists the connection — replacing any previous
     * connection for the same subject and provider.
     */
    readonly complete: (
      input: CompleteOAuthInput,
    ) => Effect.Effect<OAuthConnection, CompleteOAuthError>;
    /** The subject's current connection, if any. Token fields stay `Redacted`. */
    readonly connection: (
      provider: OAuthProviderKey,
      subjectId: SubjectId,
    ) => Effect.Effect<Option.Option<OAuthConnection>, AuthStoreError>;
    /**
     * A currently valid access token for the subject, refreshing (and
     * persisting) it first when it is at or past the refresh margin. Fails
     * with `OAuthReauthorizationRequired` when no live refresh path exists or
     * the provider rejects the refresh grant.
     */
    readonly accessToken: (
      provider: OAuthProviderKey,
      subjectId: SubjectId,
    ) => Effect.Effect<
      Redacted.Redacted<string>,
      | UnknownOAuthProvider
      | OAuthConnectionNotFound
      | OAuthReauthorizationRequired
      | OAuthProviderError
      | AuthStoreError
    >;
    /**
     * Revokes the provider grant (when the provider supports revocation) and
     * removes the stored connection. Idempotent: succeeds when no connection
     * exists. A failed revocation keeps the connection so the caller can
     * retry.
     */
    readonly disconnect: (
      provider: OAuthProviderKey,
      subjectId: SubjectId,
    ) => Effect.Effect<void, UnknownOAuthProvider | OAuthProviderError | AuthStoreError>;
  }
>()("effect-auth/OAuth") {
  static readonly layer: Layer.Layer<
    OAuth,
    never,
    | OAuthProviders
    | OAuthStateStore
    | OAuthConnectionStore
    | AuthTokenCodec
    | Crypto.Crypto
    | HttpClient.HttpClient
  > = Layer.effect(OAuth)(
    Effect.gen(function* () {
      const policy = yield* OAuthPolicy;
      const providers = yield* OAuthProviders;
      const states = yield* OAuthStateStore;
      const connections = yield* OAuthConnectionStore;
      const codec = yield* AuthTokenCodec;
      const crypto = yield* Crypto.Crypto;
      const client = yield* HttpClient.HttpClient;

      const randomStateToken = crypto.randomBytes(32).pipe(
        Effect.map(Encoding.encodeBase64Url),
        Effect.mapError(() => AuthTokenError.make({ message: "Secure randomness unavailable" })),
      );

      const unavailable = (provider: OAuthProviderKey, endpoint: string) =>
        OAuthProviderError.make({
          provider,
          message: `The provider's ${endpoint} could not be reached`,
        });

      /**
       * One token-endpoint call. Providers such as GitHub answer errors with
       * status 200 and RFC-compliant providers answer them with status 400,
       * so the payload — not the status — decides the outcome.
       */
      const requestTokenGrant = Effect.fn("OAuth.requestTokenGrant")(function* (
        provider: OAuthProvider,
        grantParams: Readonly<Record<string, string>>,
      ): Effect.fn.Return<OAuthTokenGrant, OAuthGrantRejected | OAuthProviderError> {
        const request = HttpClientRequest.post(provider.endpoints.token).pipe(
          HttpClientRequest.acceptJson,
          HttpClientRequest.bodyUrlParams({
            ...grantParams,
            client_id: provider.clientId,
            client_secret: Redacted.value(provider.clientSecret),
          }),
        );

        const response = yield* client
          .execute(request)
          .pipe(Effect.mapError(() => unavailable(provider.key, "token endpoint")));

        const payload = yield* response.json.pipe(
          Effect.mapError(() =>
            OAuthProviderError.make({
              provider: provider.key,
              message: "The token endpoint returned a non-JSON response",
            }),
          ),
        );

        return yield* provider.decodeTokenGrant(payload);
      });

      const fetchIdentity = Effect.fn("OAuth.fetchIdentity")(function* (
        provider: OAuthProvider,
        accessToken: Redacted.Redacted<string>,
      ) {
        const request = HttpClientRequest.get(provider.identity.url).pipe(
          HttpClientRequest.acceptJson,
          HttpClientRequest.setHeaders(provider.identity.headers),
          HttpClientRequest.bearerToken(accessToken),
        );

        const response = yield* client.execute(request).pipe(
          Effect.flatMap(HttpClientResponse.filterStatusOk),
          Effect.mapError(() => unavailable(provider.key, "identity endpoint")),
        );

        const payload = yield* response.json.pipe(
          Effect.mapError(() =>
            OAuthProviderError.make({
              provider: provider.key,
              message: "The identity endpoint returned a non-JSON response",
            }),
          ),
        );

        return yield* provider.identity.decode(payload);
      });

      const tokensFromGrant = (grant: OAuthTokenGrant, now: DateTime.Utc) =>
        OAuthTokens.make({
          accessToken: grant.accessToken,
          tokenType: grant.tokenType,
          accessTokenExpiresAt: Option.map(grant.expiresIn, (lifetime) =>
            DateTime.addDuration(now, lifetime),
          ),
          refreshToken: grant.refreshToken,
          refreshTokenExpiresAt: Option.map(grant.refreshTokenExpiresIn, (lifetime) =>
            DateTime.addDuration(now, lifetime),
          ),
          scope: grant.scope,
        });

      return OAuth.of({
        begin: Effect.fn("OAuth.begin")(function* (input) {
          const provider = yield* providers.lookup(input.provider);
          const stateToken = yield* randomStateToken;
          const stateDigest = yield* codec.digestToken(Redacted.make(stateToken), stateTokenScope);
          const now = yield* DateTime.now;
          const expiresAt = DateTime.addDuration(now, policy.stateLifetime);

          yield* states.issue(
            OAuthState.make({
              stateDigest,
              provider: provider.key,
              subjectId: input.subjectId,
              redirectUri: input.redirectUri,
              issuedAt: now,
              expiresAt,
            }),
          );

          // An unparseable authorization endpoint is a provider-configuration
          // defect, not a request failure.
          const url = yield* Effect.try(() => new URL(provider.endpoints.authorization)).pipe(
            Effect.orDie,
          );

          url.searchParams.set("client_id", provider.clientId);
          url.searchParams.set("redirect_uri", input.redirectUri);
          url.searchParams.set("response_type", "code");
          url.searchParams.set("state", stateToken);
          if (provider.scopes.length > 0) {
            url.searchParams.set("scope", provider.scopes.join(" "));
          }
          for (const [name, value] of Object.entries(provider.authorizationParams)) {
            url.searchParams.set(name, value);
          }

          return OAuthAuthorization.make({ url: url.toString(), expiresAt });
        }),

        complete: Effect.fn("OAuth.complete")(function* (input) {
          const provider = yield* providers.lookup(input.provider);

          const params = yield* decodeCallbackParams(input.params).pipe(
            Effect.mapError(() => InvalidOAuthState.make()),
          );

          if (params.state === undefined || params.state === "") {
            return yield* InvalidOAuthState.make();
          }

          // The state is consumed before anything else is inspected, so every
          // callback — including a denied or malformed one — burns it.
          const stateDigest = yield* codec.digestToken(
            Redacted.make(params.state),
            stateTokenScope,
          );

          const state = yield* states.consume(stateDigest);

          if (
            state.provider !== provider.key ||
            state.subjectId !== input.subjectId ||
            state.redirectUri !== input.redirectUri
          ) {
            return yield* InvalidOAuthState.make();
          }
          if (params.error === "access_denied") {
            return yield* OAuthAccessDenied.make();
          }
          if (params.error !== undefined) {
            return yield* OAuthProviderError.make({
              provider: provider.key,
              message: "The provider rejected the authorization request",
            });
          }
          if (params.code === undefined || params.code === "") {
            return yield* InvalidOAuthState.make();
          }

          const grant = yield* requestTokenGrant(provider, {
            grant_type: "authorization_code",
            code: params.code,
            redirect_uri: input.redirectUri,
          }).pipe(
            Effect.catchTag(
              "OAuthGrantRejected",
              (rejection): Effect.Effect<never, OAuthAccessDenied | OAuthProviderError> =>
                rejection.code === "access_denied"
                  ? OAuthAccessDenied.make()
                  : OAuthProviderError.make({
                      provider: provider.key,
                      message: `The provider rejected the code exchange (${rejection.code})`,
                    }),
            ),
          );

          const identity = yield* fetchIdentity(provider, grant.accessToken);
          const now = yield* DateTime.now;

          const connection = OAuthConnection.make({
            provider: provider.key,
            subjectId: input.subjectId,
            identity,
            tokens: tokensFromGrant(grant, now),
            connectedAt: now,
            updatedAt: now,
          });

          yield* connections.put(connection);

          return connection;
        }),

        connection: (provider, subjectId) => connections.get(provider, subjectId),

        accessToken: Effect.fn("OAuth.accessToken")(function* (providerKey, subjectId) {
          const existing = yield* connections.get(providerKey, subjectId);

          if (Option.isNone(existing)) {
            return yield* OAuthConnectionNotFound.make();
          }
          const current = existing.value;
          const now = yield* DateTime.now;
          const nowMillis = DateTime.toEpochMillis(now);
          const marginMillis = Duration.toMillis(policy.accessTokenRefreshMargin);

          const usable =
            Option.isNone(current.tokens.accessTokenExpiresAt) ||
            nowMillis + marginMillis <
              DateTime.toEpochMillis(current.tokens.accessTokenExpiresAt.value);

          if (usable) {
            return current.tokens.accessToken;
          }
          const refreshToken = current.tokens.refreshToken;

          const refreshTokenDead =
            Option.isNone(refreshToken) ||
            (Option.isSome(current.tokens.refreshTokenExpiresAt) &&
              nowMillis >= DateTime.toEpochMillis(current.tokens.refreshTokenExpiresAt.value));

          if (Option.isNone(refreshToken) || refreshTokenDead) {
            return yield* OAuthReauthorizationRequired.make();
          }
          const provider = yield* providers.lookup(providerKey);

          // A rejected refresh grant means the provider-side authorization is
          // gone; only a fresh authorization can repair it.
          const grant = yield* requestTokenGrant(provider, {
            grant_type: "refresh_token",
            refresh_token: Redacted.value(refreshToken.value),
          }).pipe(Effect.catchTag("OAuthGrantRejected", () => OAuthReauthorizationRequired.make()));

          const rotated = tokensFromGrant(grant, now);

          // Providers that do not rotate refresh tokens omit them from the
          // refresh response; the previous one then stays valid.
          const tokens = Option.isSome(rotated.refreshToken)
            ? rotated
            : OAuthTokens.make({
                ...rotated,
                refreshToken: current.tokens.refreshToken,
                refreshTokenExpiresAt: current.tokens.refreshTokenExpiresAt,
              });

          yield* connections.put(OAuthConnection.make({ ...current, tokens, updatedAt: now }));

          return tokens.accessToken;
        }),

        disconnect: Effect.fn("OAuth.disconnect")(function* (providerKey, subjectId) {
          const existing = yield* connections.get(providerKey, subjectId);

          if (Option.isNone(existing)) {
            return;
          }
          const provider = yield* providers.lookup(providerKey);

          if (Option.isSome(provider.revocation)) {
            const response = yield* client
              .execute(provider.revocation.value(existing.value.tokens.accessToken))
              .pipe(Effect.mapError(() => unavailable(provider.key, "revocation endpoint")));

            const alreadyGone = response.status === 404 || response.status === 422;

            if (!(response.status >= 200 && response.status < 300) && !alreadyGone) {
              return yield* OAuthProviderError.make({
                provider: provider.key,
                message: "The provider refused the token revocation",
              });
            }
          }
          yield* connections.remove(providerKey, subjectId);
        }),
      });
    }),
  );
}
