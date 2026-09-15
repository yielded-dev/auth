import { Schema } from "effect";

import { SubjectId, TokenDigest } from "../Schema";

// --- Identifiers -----------------------------------------------------------

/**
 * Stable identifier of one configured OAuth provider ("github", "gitlab").
 * Doubles as the routing key for callback endpoints, so it is constrained to
 * URL-safe lowercase slugs.
 */
export const OAuthProviderKey = Schema.String.check(
  Schema.isPattern(/^[a-z][a-z0-9-]{0,63}$/),
).pipe(Schema.brand("effect-auth/OAuthProviderKey"));

export type OAuthProviderKey = typeof OAuthProviderKey.Type;

// --- Authorization state ------------------------------------------------------

/**
 * One pending authorization redirect, stored under the digest of the opaque
 * `state` token carried through the provider redirect. Binding the subject and
 * redirect URI here is what lets the callback verify that the response belongs
 * to the actor and destination that initiated it.
 */
export class OAuthState extends Schema.Class<OAuthState>("effect-auth/OAuthState")({
  stateDigest: TokenDigest,
  provider: OAuthProviderKey,
  subjectId: SubjectId,
  redirectUri: Schema.NonEmptyString,
  issuedAt: Schema.DateTimeUtcFromMillis,
  expiresAt: Schema.DateTimeUtcFromMillis,
}) {}

/** Where to send the browser to start an authorization, plus the state's expiry. */
export class OAuthAuthorization extends Schema.Class<OAuthAuthorization>(
  "effect-auth/OAuthAuthorization",
)({
  url: Schema.NonEmptyString,
  expiresAt: Schema.DateTimeUtcFromMillis,
}) {}

/**
 * The untrusted query parameters a provider redirects back with. Decoded from
 * `unknown` inside the OAuth workflow, so HTTP handlers can hand the raw
 * query record straight through.
 */
export class OAuthCallbackParams extends Schema.Class<OAuthCallbackParams>(
  "effect-auth/OAuthCallbackParams",
)({
  state: Schema.optionalKey(Schema.String),
  code: Schema.optionalKey(Schema.String),
  error: Schema.optionalKey(Schema.String),
  error_description: Schema.optionalKey(Schema.String),
}) {}

// --- Tokens -------------------------------------------------------------------

/**
 * The provider-issued token set with absolute expirations. Token values stay
 * `Redacted` end to end; persistence adapters unwrap them only at their
 * encryption boundary.
 */
export class OAuthTokens extends Schema.Class<OAuthTokens>("effect-auth/OAuthTokens")({
  accessToken: Schema.Redacted(Schema.NonEmptyString),
  /** Normalized to lowercase; "bearer" for every currently supported provider. */
  tokenType: Schema.NonEmptyString,
  /** `None` means the provider issues non-expiring access tokens. */
  accessTokenExpiresAt: Schema.Option(Schema.DateTimeUtcFromMillis),
  refreshToken: Schema.Option(Schema.Redacted(Schema.NonEmptyString)),
  refreshTokenExpiresAt: Schema.Option(Schema.DateTimeUtcFromMillis),
  scope: Schema.Option(Schema.NonEmptyString),
}) {}

// --- Identity -------------------------------------------------------------------

/**
 * The provider's account identity, validated by the provider layer. The
 * account id is the provider's *stable* identifier in string form (for GitHub,
 * the numeric user id in decimal); the handle is the mutable display login.
 */
export class OAuthIdentity extends Schema.Class<OAuthIdentity>("effect-auth/OAuthIdentity")({
  provider: OAuthProviderKey,
  providerAccountId: Schema.NonEmptyString,
  handle: Schema.Option(Schema.NonEmptyString),
}) {}

// --- Connection -------------------------------------------------------------------

/**
 * The durable link between one subject and one provider account: identity plus
 * the current token set. At most one connection exists per subject and
 * provider; completing a new authorization replaces it.
 */
export class OAuthConnection extends Schema.Class<OAuthConnection>("effect-auth/OAuthConnection")({
  provider: OAuthProviderKey,
  subjectId: SubjectId,
  identity: OAuthIdentity,
  tokens: OAuthTokens,
  connectedAt: Schema.DateTimeUtcFromMillis,
  updatedAt: Schema.DateTimeUtcFromMillis,
}) {}
