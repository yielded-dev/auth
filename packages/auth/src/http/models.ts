import { Schema } from "effect";

import { Email, SessionSummary } from "../Schema";

export class RequestEmailOtpPayload extends Schema.Class<RequestEmailOtpPayload>(
  "effect-auth/http/RequestEmailOtpPayload",
)({
  // Kept as the wire string so the handler can map Email schema failures into
  // the endpoint's stable InvalidAuthRequest body instead of a generic parser response.
  email: Schema.String,
}) {}

export class VerifyEmailOtpPayload extends Schema.Class<VerifyEmailOtpPayload>(
  "effect-auth/http/VerifyEmailOtpPayload",
)({
  code: Schema.Redacted(Schema.String),
}) {}

export class PasswordSignInPayload extends Schema.Class<PasswordSignInPayload>(
  "effect-auth/http/PasswordSignInPayload",
)({
  // Kept as the wire string so the handler can map Email schema failures into
  // the endpoint's stable InvalidAuthRequest body instead of a generic parser response.
  email: Schema.String,
  password: Schema.Redacted(Schema.String),
}) {}

export class SetPasswordPayload extends Schema.Class<SetPasswordPayload>(
  "effect-auth/http/SetPasswordPayload",
)({
  /** Required whenever the subject already has a password credential. */
  currentPassword: Schema.optionalKey(Schema.Redacted(Schema.String)),
  newPassword: Schema.Redacted(Schema.String),
}) {}

export class ExistingSessionResult extends Schema.TaggedClass<ExistingSessionResult>()(
  "ExistingSession",
  { session: SessionSummary },
) {}

export class RegistrationRequiredResult extends Schema.TaggedClass<RegistrationRequiredResult>()(
  "RegistrationRequired",
  {
    email: Email,
    registrationExpiresAt: Schema.DateTimeUtcFromMillis,
  },
) {}

export const VerifyEmailOtpResult = Schema.Union([
  ExistingSessionResult,
  RegistrationRequiredResult,
]);

export type VerifyEmailOtpResult = typeof VerifyEmailOtpResult.Type;

export class SessionStateAnonymous extends Schema.TaggedClass<SessionStateAnonymous>()(
  "Anonymous",
  {},
) {}

export class SessionStateRegistrationRequired extends Schema.TaggedClass<SessionStateRegistrationRequired>()(
  "RegistrationRequired",
  {
    email: Email,
    registrationExpiresAt: Schema.DateTimeUtcFromMillis,
  },
) {}

export class SessionStateAuthenticated extends Schema.TaggedClass<SessionStateAuthenticated>()(
  "Authenticated",
  { session: SessionSummary },
) {}

export const SessionState = Schema.Union([
  SessionStateAnonymous,
  SessionStateRegistrationRequired,
  SessionStateAuthenticated,
]);

export type SessionState = typeof SessionState.Type;
