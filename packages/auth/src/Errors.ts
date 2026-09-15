import { Schema } from "effect";

// Declared in the style of effect's `HttpApiError` module: transport-facing
// errors carry their HTTP status as a schema annotation on the class itself,
// so endpoint and middleware declarations reference the class directly.

// Expected authentication failures. OTP failure reasons (expired, missing,
// wrong, superseded, consumed, exhausted) deliberately collapse into the same
// public error so responses cannot be used to probe challenge state.

export class InvalidEmailOtp extends Schema.TaggedError<InvalidEmailOtp>()(
  "InvalidEmailOtp",
  {},
  { httpApiStatus: 401 },
) {}

export class InvalidRegistration extends Schema.TaggedError<InvalidRegistration>()(
  "InvalidRegistration",
  {},
  { httpApiStatus: 401 },
) {}

/**
 * Password sign-in failure modes (unknown email, no password credential, wrong
 * password) deliberately collapse into this one payload-free error so
 * responses cannot be used to enumerate accounts.
 */
export class InvalidCredentials extends Schema.TaggedError<InvalidCredentials>()(
  "InvalidCredentials",
  {},
  { httpApiStatus: 401 },
) {}

/** Never a transport error itself; session middleware maps it to `Unauthorized`. */
export class InvalidSession extends Schema.TaggedError<InvalidSession>()("InvalidSession", {}) {}

export class Unauthorized extends Schema.TaggedError<Unauthorized>()(
  "Unauthorized",
  {},
  { httpApiStatus: 401 },
) {}

export class InvalidAuthRequest extends Schema.TaggedError<InvalidAuthRequest>()(
  "InvalidAuthRequest",
  {
    message: Schema.NonEmptyString,
  },
  { httpApiStatus: 400 },
) {}

export class AuthRateLimited extends Schema.TaggedError<AuthRateLimited>()(
  "AuthRateLimited",
  {
    retryAfterSeconds: Schema.optionalKey(Schema.Natural),
  },
  { httpApiStatus: 429 },
) {}

/**
 * Registration cannot complete because the application has not yet created the
 * email-to-subject mapping for the registration's verified email.
 */
export class RegistrationIncomplete extends Schema.TaggedError<RegistrationIncomplete>()(
  "RegistrationIncomplete",
  {},
  { httpApiStatus: 409 },
) {}

// Infrastructure failures. These map to 503 at the HTTP boundary so a key or
// store outage does not silently sign users out. Messages must never contain
// tokens, codes, digests, or key material.

export class AuthUnavailable extends Schema.TaggedError<AuthUnavailable>()(
  "AuthUnavailable",
  {},
  { httpApiStatus: 503 },
) {}

export class AuthStoreError extends Schema.TaggedError<AuthStoreError>()("AuthStoreError", {
  message: Schema.NonEmptyString,
}) {
  static readonly unavailable = AuthStoreError.make({
    message: "The auth store is temporarily unavailable",
  });
}

export class AuthTokenError extends Schema.TaggedError<AuthTokenError>()("AuthTokenError", {
  message: Schema.NonEmptyString,
}) {}

export class EmailDeliveryError extends Schema.TaggedError<EmailDeliveryError>()(
  "EmailDeliveryError",
  {
    message: Schema.NonEmptyString,
  },
) {}

export class IdentityResolutionError extends Schema.TaggedError<IdentityResolutionError>()(
  "IdentityResolutionError",
  {
    message: Schema.NonEmptyString,
  },
) {}
