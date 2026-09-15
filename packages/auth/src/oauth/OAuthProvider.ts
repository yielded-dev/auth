import { Duration, Effect, Option, Redacted, Schema } from "effect";
import type { HttpClientRequest } from "effect/unstable/http";

import { OAuthGrantRejected, OAuthProviderError } from "./errors";
import type { OAuthIdentity, OAuthProviderKey } from "./schema";

/**
 * One token-endpoint grant in wire-relative form: lifetimes are durations
 * because the response carries `expires_in`, not instants. The OAuth workflow
 * stamps absolute expirations against its own clock.
 */
export interface OAuthTokenGrant {
  readonly accessToken: Redacted.Redacted<string>;
  readonly tokenType: string;
  readonly expiresIn: Option.Option<Duration.Duration>;
  readonly refreshToken: Option.Option<Redacted.Redacted<string>>;
  readonly refreshTokenExpiresIn: Option.Option<Duration.Duration>;
  readonly scope: Option.Option<string>;
}

/** Where and how the workflow fetches the provider's account identity. */
export interface OAuthIdentityEndpoint {
  readonly url: string;
  /** Static headers merged into the request; authorization is added by the workflow. */
  readonly headers: Readonly<Record<string, string>>;
  /** Validates the untrusted identity payload and normalizes it. */
  readonly decode: (payload: unknown) => Effect.Effect<OAuthIdentity, OAuthProviderError>;
}

/**
 * Everything provider-specific about one OAuth integration: endpoints,
 * credentials, response mappings, and identity normalization. Deliberately
 * data-plus-decoders — the `OAuth` workflow owns every orchestration step
 * (state, redirects, code exchange, refresh, revocation execution), so a
 * provider cannot diverge from the flow's security behavior.
 */
export interface OAuthProvider {
  readonly key: OAuthProviderKey;
  readonly displayName: string;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly endpoints: {
    readonly authorization: string;
    readonly token: string;
  };
  /** Scopes requested at authorization; when empty the `scope` parameter is omitted. */
  readonly scopes: ReadonlyArray<string>;
  /** Extra static query parameters for the authorization redirect. */
  readonly authorizationParams: Readonly<Record<string, string>>;
  /**
   * Decodes one token-endpoint JSON payload into a normalized grant, or into
   * `OAuthGrantRejected` when the payload is a well-formed OAuth error.
   * Providers following RFC 6749 use {@link decodeStandardTokenGrant}.
   */
  readonly decodeTokenGrant: (
    payload: unknown,
  ) => Effect.Effect<OAuthTokenGrant, OAuthGrantRejected | OAuthProviderError>;
  readonly identity: OAuthIdentityEndpoint;
  /**
   * Builds the provider's token-revocation request; `None` when the provider
   * offers no revocation API. The workflow executes the request and treats
   * 2xx and "grant already gone" statuses (404, 422) as revoked.
   */
  readonly revocation: Option.Option<
    (accessToken: Redacted.Redacted<string>) => HttpClientRequest.HttpClientRequest
  >;
}

// --- Standard token responses -----------------------------------------------------

const StandardTokenSuccess = Schema.Struct({
  access_token: Schema.NonEmptyString,
  token_type: Schema.optionalKey(Schema.String),
  expires_in: Schema.optionalKey(Schema.Finite),
  refresh_token: Schema.optionalKey(Schema.NonEmptyString),
  refresh_token_expires_in: Schema.optionalKey(Schema.Finite),
  scope: Schema.optionalKey(Schema.String),
});

const StandardTokenError = Schema.Struct({
  error: Schema.NonEmptyString,
});

const StandardTokenResponse = Schema.Union([StandardTokenSuccess, StandardTokenError]);

// oxlint-disable-next-line no-restricted-properties -- Token endpoint payloads are untrusted JSON.
const decodeStandardTokenResponse = Schema.decodeUnknownEffect(StandardTokenResponse);

const positiveSeconds = (seconds: number | undefined): Option.Option<Duration.Duration> =>
  seconds !== undefined && seconds > 0 ? Option.some(Duration.seconds(seconds)) : Option.none();

/**
 * Token-grant decoder for RFC 6749 token responses (`access_token`,
 * `expires_in`, `refresh_token`, …) that also recognizes the standard
 * `{ "error": … }` payload — which some providers, GitHub included, return
 * with status 200.
 */
export const decodeStandardTokenGrant =
  (provider: OAuthProviderKey) =>
  (payload: unknown): Effect.Effect<OAuthTokenGrant, OAuthGrantRejected | OAuthProviderError> =>
    decodeStandardTokenResponse(payload).pipe(
      Effect.mapError(() =>
        OAuthProviderError.make({
          provider,
          message: "The token endpoint returned an unrecognized response",
        }),
      ),
      Effect.flatMap((response) =>
        "error" in response
          ? OAuthGrantRejected.make({ provider, code: response.error })
          : Effect.succeed<OAuthTokenGrant>({
              accessToken: Redacted.make(response.access_token),
              tokenType: (response.token_type ?? "bearer").toLowerCase(),
              expiresIn: positiveSeconds(response.expires_in),
              refreshToken:
                response.refresh_token !== undefined
                  ? Option.some(Redacted.make(response.refresh_token))
                  : Option.none(),
              refreshTokenExpiresIn: positiveSeconds(response.refresh_token_expires_in),
              scope:
                response.scope !== undefined && response.scope !== ""
                  ? Option.some(response.scope)
                  : Option.none(),
            }),
      ),
    );
