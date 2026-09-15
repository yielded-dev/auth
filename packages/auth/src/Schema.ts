import { Schema, SchemaGetter } from "effect";

// --- Identifiers -----------------------------------------------------------

const uuid = <Brand extends string>(brand: Brand) =>
  Schema.String.check(Schema.isUUID()).pipe(Schema.brand(brand));

export const ChallengeId = uuid("effect-auth/ChallengeId");
export type ChallengeId = typeof ChallengeId.Type;

export const RegistrationId = uuid("effect-auth/RegistrationId");
export type RegistrationId = typeof RegistrationId.Type;

export const SessionTokenId = uuid("effect-auth/SessionTokenId");
export type SessionTokenId = typeof SessionTokenId.Type;

/** Opaque application subject. The consumer maps it to its own account id. */
export const SubjectId = Schema.NonEmptyString.pipe(Schema.brand("effect-auth/SubjectId"));
export type SubjectId = typeof SubjectId.Type;

export const KeyId = Schema.NonEmptyString.pipe(Schema.brand("effect-auth/KeyId"));
export type KeyId = typeof KeyId.Type;

/** Digest of a high-entropy opaque token (challenge/registration). Never the raw token. */
export const TokenDigest = Schema.NonEmptyString.pipe(Schema.brand("effect-auth/TokenDigest"));
export type TokenDigest = typeof TokenDigest.Type;

/** Keyed digest of a low-entropy OTP code. Never the plaintext code. */
export const OtpDigest = Schema.NonEmptyString.pipe(Schema.brand("effect-auth/OtpDigest"));
export type OtpDigest = typeof OtpDigest.Type;

/** Signed session envelope in its transport form. */
export const SessionToken = Schema.NonEmptyString.pipe(Schema.brand("effect-auth/SessionToken"));
export type SessionToken = typeof SessionToken.Type;

/**
 * PHC-style encoded password verifier,
 * `pbkdf2-sha256$<iterations>$<base64url salt>$<base64url dk>`. Never the
 * plaintext password. The format is owned by `PasswordHasher`; everything else
 * treats the value as opaque.
 */
export const PasswordHash = Schema.NonEmptyString.pipe(Schema.brand("effect-auth/PasswordHash"));
export type PasswordHash = typeof PasswordHash.Type;

// --- Email ------------------------------------------------------------------

/**
 * Ordinary ASCII addresses only; internationalized email is deferred. The
 * normalized (trimmed, fully lowercased) value is the identity key.
 */
const asciiEmailPattern =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export const Email = Schema.String.pipe(
  Schema.decodeTo(
    Schema.String.check(Schema.isPattern(asciiEmailPattern)).pipe(
      Schema.brand("effect-auth/Email"),
    ),
    {
      decode: SchemaGetter.transform((value: string) => value.trim().toLowerCase()),
      encode: SchemaGetter.transform((value: string) => value),
    },
  ),
);

export type Email = typeof Email.Type;

// --- Purposes ---------------------------------------------------------------

export const ChallengePurpose = Schema.Literal("sign-in");
export type ChallengePurpose = typeof ChallengePurpose.Type;

export const RegistrationPurpose = Schema.Literal("registration");
export type RegistrationPurpose = typeof RegistrationPurpose.Type;

// --- Challenge --------------------------------------------------------------

export class VerifiedEmail extends Schema.Class<VerifiedEmail>("effect-auth/VerifiedEmail")({
  email: Email,
  purpose: ChallengePurpose,
}) {}

export class NewChallenge extends Schema.Class<NewChallenge>("effect-auth/NewChallenge")({
  challengeId: ChallengeId,
  tokenDigest: TokenDigest,
  email: Email,
  purpose: ChallengePurpose,
  otpDigest: OtpDigest,
  /** Keyring entry used for the OTP digest, so rotation keeps in-flight challenges valid. */
  otpKeyId: KeyId,
  issuedAt: Schema.DateTimeUtcFromMillis,
  expiresAt: Schema.DateTimeUtcFromMillis,
  attemptLimit: Schema.Natural,
  resendCooldown: Schema.DurationFromMillis,
}) {}

export class ConsumeChallenge extends Schema.Class<ConsumeChallenge>(
  "effect-auth/ConsumeChallenge",
)({
  tokenDigest: TokenDigest,
  /**
   * Candidate OTP digests keyed by keyring entry. The store compares the
   * candidate matching the key id recorded on the challenge, in constant time.
   */
  otpDigests: Schema.Record(KeyId, OtpDigest),
}) {}

// --- Pending registration ----------------------------------------------------

export class NewRegistration extends Schema.Class<NewRegistration>("effect-auth/NewRegistration")({
  registrationId: RegistrationId,
  tokenDigest: TokenDigest,
  email: Email,
  purpose: RegistrationPurpose,
  issuedAt: Schema.DateTimeUtcFromMillis,
  expiresAt: Schema.DateTimeUtcFromMillis,
}) {}

export class PendingRegistration extends Schema.Class<PendingRegistration>(
  "effect-auth/PendingRegistration",
)({
  registrationId: RegistrationId,
  email: Email,
  purpose: RegistrationPurpose,
  issuedAt: Schema.DateTimeUtcFromMillis,
  expiresAt: Schema.DateTimeUtcFromMillis,
}) {}

export class ConsumeRegistration extends Schema.Class<ConsumeRegistration>(
  "effect-auth/ConsumeRegistration",
)({
  tokenDigest: TokenDigest,
}) {}

// --- Session ----------------------------------------------------------------

/**
 * Claims carried by the signed session envelope. `ext` contains app-defined
 * claims and is opaque to effect-auth. The envelope is signed, not encrypted,
 * so applications must treat extension values as client-readable.
 */
export class SessionClaims extends Schema.Class<SessionClaims>("effect-auth/SessionClaims")({
  /** Envelope format version. */
  ver: Schema.Literal(1),
  /** Configured session generation; incrementing invalidates all prior sessions. */
  gen: Schema.Natural,
  kid: KeyId,
  sub: SubjectId,
  /** App-defined claims, opaque to effect-auth. */
  ext: Schema.optionalKey(Schema.Unknown),
  iss: Schema.NonEmptyString,
  aud: Schema.NonEmptyString,
  iat: Schema.DateTimeUtcFromMillis,
  exp: Schema.DateTimeUtcFromMillis,
  jti: SessionTokenId,
}) {}

/** Public, cookie-free view of an issued session. */
export class SessionSummary extends Schema.Class<SessionSummary>("effect-auth/SessionSummary")({
  subjectId: SubjectId,
  expiresAt: Schema.DateTimeUtcFromMillis,
}) {}

// --- Password credential ------------------------------------------------------

/**
 * Long-lived password credential state for one subject. Lives behind
 * `PasswordCredentialStore`, never in `AuthStore` (which is transient-only).
 */
export class PasswordCredential extends Schema.Class<PasswordCredential>(
  "effect-auth/PasswordCredential",
)({
  subjectId: SubjectId,
  hash: PasswordHash,
  failedAttempts: Schema.Natural,
  lockedUntil: Schema.Option(Schema.DateTimeUtcFromMillis),
}) {}

// --- Sender -----------------------------------------------------------------

export class EmailOtpMessage extends Schema.Class<EmailOtpMessage>("effect-auth/EmailOtpMessage")({
  email: Email,
  code: Schema.Redacted(Schema.String),
  expiresAt: Schema.DateTimeUtcFromMillis,
}) {}

// --- Digests ----------------------------------------------------------------

export class KeyedDigest extends Schema.Class<KeyedDigest>("effect-auth/KeyedDigest")({
  keyId: KeyId,
  digest: OtpDigest,
}) {}

// --- Workflow results -------------------------------------------------------

export class EmailOtpChallenge extends Schema.Class<EmailOtpChallenge>(
  "effect-auth/EmailOtpChallenge",
)({
  challengeToken: Schema.Redacted(Schema.String),
  expiresAt: Schema.DateTimeUtcFromMillis,
}) {}

export class ExistingSubject extends Schema.TaggedClass<ExistingSubject>()("ExistingSubject", {
  subjectId: SubjectId,
  email: Email,
}) {}

export class RegistrationRequired extends Schema.TaggedClass<RegistrationRequired>()(
  "RegistrationRequired",
  {
    registrationToken: Schema.Redacted(Schema.String),
    email: Email,
    expiresAt: Schema.DateTimeUtcFromMillis,
  },
) {}

export const EmailOtpVerification = Schema.Union([ExistingSubject, RegistrationRequired]);
export type EmailOtpVerification = typeof EmailOtpVerification.Type;

// --- Constant-time comparison ------------------------------------------------

/**
 * Constant-time string comparison for digest values. Scans the full length of
 * both inputs regardless of where they diverge.
 */
export const timingSafeStringEqual = (a: string, b: string): boolean => {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;

  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) | 0) ^ (b.charCodeAt(i) | 0);
  }

  return diff === 0;
};
