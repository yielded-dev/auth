import { Context, DateTime, Duration, Effect, Layer } from "effect";

import { InvalidSession } from "./Errors";
import type { SessionClaims } from "./Schema";

export interface AuthPolicyShape {
  /** OTP challenge lifetime. */
  readonly otpLifetime: Duration.Duration;
  /** Number of decimal digits in the OTP code. */
  readonly otpLength: number;
  /** Rolling wrong-code budget per email and purpose. */
  readonly attemptLimit: number;
  /** Minimum delay between challenge issuances for the same email and purpose. */
  readonly resendCooldown: Duration.Duration;
  /** Pending-registration lifetime. */
  readonly registrationLifetime: Duration.Duration;
  /** Lifetime of each issued session token. */
  readonly sessionLifetime: Duration.Duration;
  /** Minimum token age before authenticated HTTP activity may renew it. */
  readonly sessionRenewalInterval: Duration.Duration;
  /** `iss` claim issued and required on session tokens. */
  readonly issuer: string;
  /** `aud` claim issued and required on session tokens. */
  readonly audience: string;
  /** Incrementing this invalidates every previously issued session. */
  readonly sessionGeneration: number;
  /** Minimum accepted password length. */
  readonly passwordMinLength: number;
  /** Maximum accepted password length; bounds the PBKDF2 work per attempt. */
  readonly passwordMaxLength: number;
  /** PBKDF2-HMAC-SHA-256 iteration count for newly hashed passwords. */
  readonly passwordIterations: number;
  /** Consecutive failed password sign-ins before the credential locks. */
  readonly passwordAttemptLimit: number;
  /** How long a locked credential rejects sign-in attempts. */
  readonly passwordLockDuration: Duration.Duration;
}

// Numbers match the sign-in design spec (Auth — Sign in, section 8c): a
// six-digit code valid ten minutes, resend unlocked after thirty seconds,
// three wrong attempts before the code is invalidated. The password iteration
// count follows the OWASP 2023+ recommendation for PBKDF2-HMAC-SHA-256.
export const defaultAuthPolicy: AuthPolicyShape = {
  otpLifetime: Duration.minutes(10),
  otpLength: 6,
  attemptLimit: 3,
  resendCooldown: Duration.seconds(30),
  registrationLifetime: Duration.minutes(15),
  sessionLifetime: Duration.days(7),
  sessionRenewalInterval: Duration.days(1),
  issuer: "effect-auth",
  audience: "effect-auth",
  sessionGeneration: 0,
  passwordMinLength: 8,
  passwordMaxLength: 256,
  passwordIterations: 600_000,
  passwordAttemptLimit: 10,
  passwordLockDuration: Duration.minutes(15),
};

export const AuthPolicy = Context.Reference<AuthPolicyShape>("effect-auth/AuthPolicy", {
  defaultValue: () => defaultAuthPolicy,
});

/** The signed-claim subset that remains meaningful after token verification. */
export interface SessionClaimsPolicy {
  readonly issuer: string;
  readonly audience: string;
  readonly sessionGeneration: number;
  readonly allowedSigningKeyIds: ReadonlySet<string>;
}

/** Revalidates a previously verified claim set at each later trust boundary. */
export const revalidateSessionClaims = Effect.fn("AuthSession.revalidateClaims")(function* (
  claims: SessionClaims,
  policy: SessionClaimsPolicy,
) {
  const now = yield* DateTime.now;

  if (
    DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(claims.exp) ||
    claims.gen !== policy.sessionGeneration ||
    claims.iss !== policy.issuer ||
    claims.aud !== policy.audience ||
    !policy.allowedSigningKeyIds.has(claims.kid)
  ) {
    return yield* InvalidSession.make();
  }

  return claims;
});

/** Builds an auth policy layer by overriding the secure library defaults. */
export const layerAuthPolicy = (overrides: Partial<AuthPolicyShape> = {}) =>
  Layer.succeed(AuthPolicy)({ ...defaultAuthPolicy, ...overrides });
