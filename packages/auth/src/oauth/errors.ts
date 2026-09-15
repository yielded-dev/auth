import { Schema } from "effect";

import { OAuthProviderKey } from "./schema";

// Declared in the style of the package's root `errors.ts`: expected
// transport-facing errors carry their HTTP status as a schema annotation;
// infrastructure failures carry none and are mapped at the HTTP boundary.
// Messages must never contain tokens, codes, or state values.

/** The callback names a provider the application did not configure. */
export class UnknownOAuthProvider extends Schema.TaggedError<UnknownOAuthProvider>()(
  "UnknownOAuthProvider",
  {
    provider: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

/**
 * Authorization state failure. The reasons (missing, unknown, expired,
 * already consumed, wrong subject, wrong provider, wrong redirect URI, missing
 * code) deliberately collapse into one payload-free error so callback
 * responses cannot be used to probe state.
 */
export class InvalidOAuthState extends Schema.TaggedError<InvalidOAuthState>()(
  "InvalidOAuthState",
  {},
  { httpApiStatus: 401 },
) {}

/** The actor declined the provider's consent screen. */
export class OAuthAccessDenied extends Schema.TaggedError<OAuthAccessDenied>()(
  "OAuthAccessDenied",
  {},
  { httpApiStatus: 403 },
) {}

/**
 * No usable access token exists for the subject: the access token expired and
 * there is no live refresh token, or the provider rejected the refresh grant.
 * The application must send the actor back through {@link OAuth.begin}.
 */
export class OAuthReauthorizationRequired extends Schema.TaggedError<OAuthReauthorizationRequired>()(
  "OAuthReauthorizationRequired",
  {},
  { httpApiStatus: 409 },
) {}

/** The subject has no connection for the provider. */
export class OAuthConnectionNotFound extends Schema.TaggedError<OAuthConnectionNotFound>()(
  "OAuthConnectionNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * The provider's token endpoint answered with a well-formed OAuth error
 * payload. Raised by provider token-grant decoders; the workflow maps it to
 * `OAuthAccessDenied`, `OAuthReauthorizationRequired`, or
 * `OAuthProviderError` depending on the grant being attempted.
 */
export class OAuthGrantRejected extends Schema.TaggedError<OAuthGrantRejected>()(
  "OAuthGrantRejected",
  {
    provider: OAuthProviderKey,
    /** The provider's `error` code (e.g. `access_denied`, `bad_verification_code`). */
    code: Schema.NonEmptyString,
  },
) {}

/** The provider is unreachable or answered outside its contract. */
export class OAuthProviderError extends Schema.TaggedError<OAuthProviderError>()(
  "OAuthProviderError",
  {
    provider: OAuthProviderKey,
    message: Schema.NonEmptyString,
  },
) {}
