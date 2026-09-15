import { Context, DateTime, Effect, Layer, Option, Redacted } from "effect";

import {
  type AuthStoreError,
  type AuthTokenError,
  AuthRateLimited,
  InvalidAuthRequest,
  InvalidCredentials,
} from "./Errors";
import { PasswordCredentialStore } from "./PasswordCredentialStore";
import { PasswordHasher } from "./PasswordHasher";
import { AuthPolicy } from "./Policy";
import type { Email, SubjectId } from "./Schema";

export interface SetPasswordInput {
  /** Required whenever the subject already has a password credential. */
  readonly currentPassword: Option.Option<Redacted.Redacted<string>>;
  readonly newPassword: Redacted.Redacted<string>;
}

/**
 * Password strategy workflow, a sibling of `EmailOtp`. A password is a second
 * sign-in method an existing subject opts into; account creation stays with
 * the email OTP strategy, so a verified email always precedes a credential.
 * Session issuance stays in `AuthSession`; the HTTP layer composes the two.
 *
 * Sessions are stateless, so changing a password does not revoke sessions
 * issued before the change.
 */
export class PasswordAuth extends Context.Service<
  PasswordAuth,
  {
    /**
     * Verifies an email and password pair and resolves the subject. Unknown
     * email, missing credential, and wrong password all collapse into
     * `InvalidCredentials`; a locked credential is `AuthRateLimited`.
     */
    readonly signIn: (
      email: Email,
      password: Redacted.Redacted<string>,
    ) => Effect.Effect<
      SubjectId,
      InvalidCredentials | AuthRateLimited | AuthStoreError | AuthTokenError
    >;
    /**
     * Sets or changes the subject's password. Changing an existing password
     * requires the current one; a missing or wrong current password is
     * `InvalidCredentials`, and a new password outside the policy bounds is
     * `InvalidAuthRequest`. Wrong current passwords share the sign-in failure
     * accounting, so a locked credential is `AuthRateLimited` here too —
     * otherwise this endpoint would be an unthrottled password oracle.
     */
    readonly setPassword: (
      subjectId: SubjectId,
      input: SetPasswordInput,
    ) => Effect.Effect<
      void,
      InvalidCredentials | InvalidAuthRequest | AuthRateLimited | AuthStoreError | AuthTokenError
    >;
    /** Reports whether the subject has set a password. */
    readonly hasPassword: (subjectId: SubjectId) => Effect.Effect<boolean, AuthStoreError>;
  }
>()("effect-auth/PasswordAuth") {
  static readonly layer: Layer.Layer<
    PasswordAuth,
    never,
    PasswordCredentialStore | PasswordHasher
  > = Layer.effect(PasswordAuth)(
    Effect.gen(function* () {
      const policy = yield* AuthPolicy;
      const store = yield* PasswordCredentialStore;
      const hasher = yield* PasswordHasher;

      // Verified when no credential exists so the missing-credential path
      // costs one key derivation, the same as a wrong password. Hashed here
      // rather than hard-coded so its iteration count tracks the policy.
      // Lazily memoized rather than derived at layer build: consumers may
      // rebuild the layer graph per request, and only the unknown-email
      // sign-in path should ever pay the full key derivation.
      const dummyHash = yield* Effect.cached(
        hasher.hash(Redacted.make("effect-auth/anti-enumeration-dummy")),
      );

      const failureOptions = {
        attemptLimit: policy.passwordAttemptLimit,
        lockDuration: policy.passwordLockDuration,
      };

      return PasswordAuth.of({
        signIn: Effect.fn("PasswordAuth.signIn")(function* (email, password) {
          // An over-long password can never verify (`setPassword` enforces the
          // cap), so refuse it before any derivation. The response does not
          // depend on the email, so nothing leaks.
          if (Redacted.value(password).length > policy.passwordMaxLength) {
            return yield* InvalidCredentials.make();
          }
          const credential = yield* store.findByEmail(email);

          if (Option.isSome(credential) && Option.isSome(credential.value.lockedUntil)) {
            const now = yield* DateTime.now;
            const lockedUntil = credential.value.lockedUntil.value;

            const remainingMillis =
              DateTime.toEpochMillis(lockedUntil) - DateTime.toEpochMillis(now);

            if (remainingMillis > 0) {
              // Deliberate tradeoff: answering 429 here reveals that a
              // password credential exists for the email (an attacker can
              // probe by burning attemptLimit guesses). We accept that —
              // legitimate locked-out users need the retry guidance, and
              // collapsing to InvalidCredentials would hide the lockout.
              return yield* AuthRateLimited.make({
                retryAfterSeconds: Math.ceil(remainingMillis / 1000),
              });
            }
          }
          if (Option.isNone(credential)) {
            // Burn the same key derivation a real verification would, so
            // response timing cannot separate unknown emails from wrong
            // passwords.
            yield* hasher.verify(password, yield* dummyHash);

            return yield* InvalidCredentials.make();
          }
          const matches = yield* hasher.verify(password, credential.value.hash);

          if (!matches) {
            yield* store.recordFailure(credential.value.subjectId, failureOptions);

            return yield* InvalidCredentials.make();
          }
          yield* store.recordSuccess(credential.value.subjectId);

          return credential.value.subjectId;
        }),

        setPassword: Effect.fn("PasswordAuth.setPassword")(function* (subjectId, input) {
          const newPasswordLength = Redacted.value(input.newPassword).length;

          if (newPasswordLength < policy.passwordMinLength) {
            return yield* InvalidAuthRequest.make({
              message: `Passwords must be at least ${policy.passwordMinLength} characters`,
            });
          }
          if (newPasswordLength > policy.passwordMaxLength) {
            return yield* InvalidAuthRequest.make({
              message: `Passwords must be at most ${policy.passwordMaxLength} characters`,
            });
          }
          const existing = yield* store.findBySubject(subjectId);

          if (Option.isSome(existing)) {
            // Current-password guesses share the sign-in failure accounting,
            // so a locked credential is rejected before any verification.
            if (Option.isSome(existing.value.lockedUntil)) {
              const now = yield* DateTime.now;

              const remainingMillis =
                DateTime.toEpochMillis(existing.value.lockedUntil.value) -
                DateTime.toEpochMillis(now);

              if (remainingMillis > 0) {
                return yield* AuthRateLimited.make({
                  retryAfterSeconds: Math.ceil(remainingMillis / 1000),
                });
              }
            }
            if (Option.isNone(input.currentPassword)) {
              return yield* InvalidCredentials.make();
            }
            const currentPassword = input.currentPassword.value;

            // Same DoS guard as sign-in: never derive from an over-long input.
            if (Redacted.value(currentPassword).length > policy.passwordMaxLength) {
              return yield* InvalidCredentials.make();
            }
            const matches = yield* hasher.verify(currentPassword, existing.value.hash);

            if (!matches) {
              yield* store.recordFailure(subjectId, failureOptions);

              return yield* InvalidCredentials.make();
            }
            yield* store.recordSuccess(subjectId);
          }
          const hash = yield* hasher.hash(input.newPassword);

          yield* store.upsert(subjectId, hash);
        }),

        hasPassword: Effect.fn("PasswordAuth.hasPassword")(function* (subjectId) {
          return Option.isSome(yield* store.findBySubject(subjectId));
        }),
      });
    }),
  );
}
