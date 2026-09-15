import {
  Context,
  Crypto,
  DateTime,
  Effect,
  Encoding,
  Layer,
  Option,
  Redacted,
  Schema,
} from "effect";

import { AuthStore } from "./AuthStore";
import { AuthTokenCodec } from "./AuthTokenCodec";
import { EmailOtpSender } from "./EmailOtpSender";
import {
  type AuthRateLimited,
  type AuthStoreError,
  type EmailDeliveryError,
  type IdentityResolutionError,
  type InvalidRegistration,
  AuthTokenError,
  InvalidEmailOtp,
  RegistrationIncomplete,
} from "./Errors";
import { IdentityResolver } from "./IdentityResolver";
import { AuthPolicy } from "./Policy";
import {
  type Email,
  type EmailOtpVerification,
  type PendingRegistration,
  type KeyId,
  type OtpDigest,
  type SubjectId,
  type TokenDigest,
  ChallengeId,
  ConsumeChallenge,
  ConsumeRegistration,
  EmailOtpChallenge,
  EmailOtpMessage,
  ExistingSubject,
  NewChallenge,
  NewRegistration,
  RegistrationId,
  RegistrationRequired,
} from "./Schema";

const challengeTokenScope = "effect-auth/challenge-token";
const registrationTokenScope = "effect-auth/registration-token";
const otpScope = (tokenDigest: TokenDigest) => `effect-auth/otp:sign-in:${tokenDigest}`;

const decodeChallengeId = Schema.decodeEffect(ChallengeId);
const decodeRegistrationId = Schema.decodeEffect(RegistrationId);

export interface VerifyEmailOtpInput {
  readonly challengeToken: Redacted.Redacted<string>;
  readonly code: Redacted.Redacted<string>;
}

/**
 * Email OTP strategy workflow. Session issuance stays in `AuthSession`; the
 * HTTP layer composes the two.
 */
export class EmailOtp extends Context.Service<
  EmailOtp,
  {
    /**
     * Creates and persists an expiring challenge, sends the code, and returns
     * the opaque challenge token for the challenge cookie.
     */
    readonly request: (
      email: Email,
    ) => Effect.Effect<
      EmailOtpChallenge,
      AuthRateLimited | AuthStoreError | AuthTokenError | EmailDeliveryError
    >;
    /**
     * Atomically consumes the challenge and resolves the subject. An unknown
     * email yields a pending registration, not an account.
     */
    readonly verify: (
      input: VerifyEmailOtpInput,
    ) => Effect.Effect<
      EmailOtpVerification,
      InvalidEmailOtp | AuthStoreError | AuthTokenError | IdentityResolutionError
    >;
    /** Resolves an unconsumed pending registration for onboarding middleware. */
    readonly inspectRegistration: (
      registrationToken: Redacted.Redacted<string>,
    ) => Effect.Effect<PendingRegistration, InvalidRegistration | AuthStoreError | AuthTokenError>;
    /**
     * Re-runs identity resolution and atomically consumes the registration. Fails
     * with `RegistrationIncomplete` until the application has created the
     * email-to-subject mapping.
     */
    readonly completeRegistration: (
      registrationToken: Redacted.Redacted<string>,
    ) => Effect.Effect<
      SubjectId,
      | InvalidRegistration
      | RegistrationIncomplete
      | AuthStoreError
      | AuthTokenError
      | IdentityResolutionError
    >;
  }
>()("effect-auth/EmailOtp") {
  static readonly layer: Layer.Layer<
    EmailOtp,
    never,
    AuthStore | EmailOtpSender | IdentityResolver | AuthTokenCodec | Crypto.Crypto
  > = Layer.effect(EmailOtp)(
    Effect.gen(function* () {
      const policy = yield* AuthPolicy;
      const store = yield* AuthStore;
      const sender = yield* EmailOtpSender;
      const resolver = yield* IdentityResolver;
      const codec = yield* AuthTokenCodec;
      const crypto = yield* Crypto.Crypto;

      const randomnessUnavailable = AuthTokenError.make({
        message: "Secure randomness unavailable",
      });

      const randomToken = crypto.randomBytes(32).pipe(
        Effect.map(Encoding.encodeBase64Url),
        Effect.mapError(() => randomnessUnavailable),
      );

      const randomUuid = crypto.randomUUIDv4.pipe(Effect.mapError(() => randomnessUnavailable));

      const randomOtp = crypto.randomIntBetween(0, 10 ** policy.otpLength, { halfOpen: true }).pipe(
        Effect.map((value) => String(value).padStart(policy.otpLength, "0")),
        Effect.mapError(() => randomnessUnavailable),
      );

      return EmailOtp.of({
        request: Effect.fn("EmailOtp.request")(function* (email) {
          const now = yield* DateTime.now;
          const expiresAt = DateTime.addDuration(now, policy.otpLifetime);
          const challengeId = yield* decodeChallengeId(yield* randomUuid).pipe(Effect.orDie);
          const token = yield* randomToken;
          const otp = yield* randomOtp;
          const tokenDigest = yield* codec.digestToken(Redacted.make(token), challengeTokenScope);
          const otpDigest = yield* codec.digestSecret(Redacted.make(otp), otpScope(tokenDigest));

          yield* store.issueChallenge(
            NewChallenge.make({
              challengeId,
              tokenDigest,
              email,
              purpose: "sign-in",
              otpDigest: otpDigest.digest,
              otpKeyId: otpDigest.keyId,
              issuedAt: now,
              expiresAt,
              attemptLimit: policy.attemptLimit,
              resendCooldown: policy.resendCooldown,
            }),
          );
          yield* sender.send(EmailOtpMessage.make({ email, code: Redacted.make(otp), expiresAt }));

          return EmailOtpChallenge.make({ challengeToken: Redacted.make(token), expiresAt });
        }),

        verify: Effect.fn("EmailOtp.verify")(function* ({ challengeToken, code }) {
          const tokenDigest = yield* codec.digestToken(challengeToken, challengeTokenScope);
          const scope = otpScope(tokenDigest);
          const otpDigests: Record<KeyId, OtpDigest> = {};

          for (const keyId of codec.keyIds) {
            const keyed = yield* codec.digestSecret(code, scope, keyId);

            otpDigests[keyed.keyId] = keyed.digest;
          }

          const verified = yield* store
            .consumeChallenge(ConsumeChallenge.make({ tokenDigest, otpDigests }))
            .pipe(
              Effect.catchTag("EmailOtpRejected", (rejection) =>
                Effect.logInfo("Email OTP verification rejected").pipe(
                  Effect.annotateLogs({
                    "auth.method": "email_otp",
                    "auth.outcome": "rejected",
                    "auth.reason": rejection.reason,
                  }),
                  Effect.andThen(InvalidEmailOtp.make()),
                ),
              ),
            );

          const subject = yield* resolver.findByVerifiedEmail(verified.email);

          if (Option.isSome(subject)) {
            return ExistingSubject.make({ subjectId: subject.value, email: verified.email });
          }
          const now = yield* DateTime.now;
          const expiresAt = DateTime.addDuration(now, policy.registrationLifetime);
          const registrationId = yield* decodeRegistrationId(yield* randomUuid).pipe(Effect.orDie);
          const registrationToken = yield* randomToken;

          const registrationDigest = yield* codec.digestToken(
            Redacted.make(registrationToken),
            registrationTokenScope,
          );

          yield* store.issueRegistration(
            NewRegistration.make({
              registrationId,
              tokenDigest: registrationDigest,
              email: verified.email,
              purpose: "registration",
              issuedAt: now,
              expiresAt,
            }),
          );

          return RegistrationRequired.make({
            registrationToken: Redacted.make(registrationToken),
            email: verified.email,
            expiresAt,
          });
        }),

        inspectRegistration: Effect.fn("EmailOtp.inspectRegistration")(
          function* (registrationToken) {
            const tokenDigest = yield* codec.digestToken(registrationToken, registrationTokenScope);

            return yield* store.inspectRegistration(tokenDigest);
          },
        ),

        completeRegistration: Effect.fn("EmailOtp.completeRegistration")(
          function* (registrationToken) {
            const tokenDigest = yield* codec.digestToken(registrationToken, registrationTokenScope);
            const registration = yield* store.inspectRegistration(tokenDigest);
            const subject = yield* resolver.findByVerifiedEmail(registration.email);

            if (Option.isNone(subject)) {
              return yield* RegistrationIncomplete.make();
            }
            yield* store.consumeRegistration(ConsumeRegistration.make({ tokenDigest }));

            return subject.value;
          },
        ),
      });
    }),
  );
}
