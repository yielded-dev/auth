import { Context, DateTime, type Duration, Effect, Layer, Option } from "effect";

import { AuthStoreError } from "./Errors";
import { IdentityResolver } from "./IdentityResolver";
import { type Email, type PasswordHash, type SubjectId, PasswordCredential } from "./Schema";

/** Failure-accounting knobs, passed per call so the store stays policy-free. */
export interface RecordFailureOptions {
  /** Consecutive failures at which the credential locks. */
  readonly attemptLimit: number;
  /** How long the credential stays locked once the limit is reached. */
  readonly lockDuration: Duration.Duration;
}

/**
 * Consumer-implemented persistence for long-lived password credentials, keyed
 * by subject with lookup through the subject's verified email. Deliberately
 * not part of `AuthStore`: that store is transient-only, while credentials
 * live as long as the account. Like `IdentityResolver`, the application owns
 * the implementation; `PasswordAuth` owns the policy decisions around it.
 */
export class PasswordCredentialStore extends Context.Service<
  PasswordCredentialStore,
  {
    readonly findByEmail: (
      email: Email,
    ) => Effect.Effect<Option.Option<PasswordCredential>, AuthStoreError>;
    readonly findBySubject: (
      subjectId: SubjectId,
    ) => Effect.Effect<Option.Option<PasswordCredential>, AuthStoreError>;
    /** Creates or replaces the subject's credential, clearing failures and any lock. */
    readonly upsert: (
      subjectId: SubjectId,
      hash: PasswordHash,
    ) => Effect.Effect<void, AuthStoreError>;
    /**
     * Increments the failure count and sets `lockedUntil` once the limit is
     * reached. A failure arriving after an existing lock has expired starts a
     * fresh window: the count resets to one and the stale lock is cleared, so
     * a single wrong attempt per window can never re-lock forever. A no-op
     * when the subject has no credential.
     */
    readonly recordFailure: (
      subjectId: SubjectId,
      options: RecordFailureOptions,
    ) => Effect.Effect<void, AuthStoreError>;
    /** Clears the failure count and any lock. A no-op when the subject has no credential. */
    readonly recordSuccess: (subjectId: SubjectId) => Effect.Effect<void, AuthStoreError>;
  }
>()("effect-auth/PasswordCredentialStore") {
  /**
   * In-memory adapter for tests and local development; never durable. Email
   * lookup delegates to `IdentityResolver`, mirroring how a production adapter
   * joins its email mapping.
   */
  static readonly layerMemory: Layer.Layer<PasswordCredentialStore, never, IdentityResolver> =
    Layer.effect(PasswordCredentialStore)(
      Effect.gen(function* () {
        const resolver = yield* IdentityResolver;
        const credentials = new Map<SubjectId, PasswordCredential>();

        const byEmail = (email: Email) =>
          resolver.findByVerifiedEmail(email).pipe(
            Effect.mapError(() => AuthStoreError.make({ message: "Identity resolution failed" })),
            Effect.map(
              Option.flatMap((subjectId) => Option.fromNullishOr(credentials.get(subjectId))),
            ),
          );

        return PasswordCredentialStore.of({
          findByEmail: byEmail,

          findBySubject: (subjectId) =>
            Effect.sync(() => Option.fromNullishOr(credentials.get(subjectId))),

          upsert: (subjectId, hash) =>
            Effect.sync(() => {
              credentials.set(
                subjectId,
                PasswordCredential.make({
                  subjectId,
                  hash,
                  failedAttempts: 0,
                  lockedUntil: Option.none(),
                }),
              );
            }),

          recordFailure: Effect.fn("PasswordCredentialStore.recordFailure")(
            function* (subjectId, options) {
              const credential = credentials.get(subjectId);

              if (credential === undefined) {
                return;
              }
              const now = yield* DateTime.now;

              // An expired lock means the previous window is over: this
              // failure starts a fresh count instead of stacking on the old
              // one, so one wrong attempt per window cannot re-lock forever.
              const lockExpired =
                Option.isSome(credential.lockedUntil) &&
                DateTime.toEpochMillis(credential.lockedUntil.value) <= DateTime.toEpochMillis(now);

              const failedAttempts = lockExpired ? 1 : credential.failedAttempts + 1;

              const lockedUntil =
                failedAttempts >= options.attemptLimit
                  ? Option.some(DateTime.addDuration(now, options.lockDuration))
                  : lockExpired
                    ? Option.none<DateTime.Utc>()
                    : credential.lockedUntil;

              credentials.set(
                subjectId,
                PasswordCredential.make({ ...credential, failedAttempts, lockedUntil }),
              );
            },
          ),

          recordSuccess: (subjectId) =>
            Effect.sync(() => {
              const credential = credentials.get(subjectId);

              if (credential === undefined) {
                return;
              }
              credentials.set(
                subjectId,
                PasswordCredential.make({
                  ...credential,
                  failedAttempts: 0,
                  lockedUntil: Option.none(),
                }),
              );
            }),
        });
      }),
    );
}
