import { DateTime, Duration, Effect, Layer, Option, Schema } from "effect";
import { TestClock } from "effect/testing";

import { IdentityResolver } from "../../IdentityResolver";
import { PasswordCredentialStore } from "../../PasswordCredentialStore";
import { type Email, type SubjectId, PasswordHash } from "../../Schema";
import { check, decodeSubjectId, emailOf } from "./support";

// Pure store-contract checks for `PasswordCredentialStore` adapters: hashes
// are opaque strings to the store, so the suite fabricates them directly and
// never needs a hasher. The adapter under test must resolve each conformance
// email to `credentialConformanceSubject` of that email; adapters that
// delegate email lookup to `IdentityResolver` (like
// `PasswordCredentialStore.layerMemory`) can use
// `layerCredentialConformanceResolver`. Run each case with `it.effect`.

export interface PasswordCredentialStoreConformanceCase {
  readonly name: string;
  readonly run: Effect.Effect<void, never, PasswordCredentialStore>;
}

const decodePasswordHash = Schema.decodeSync(PasswordHash);

/** Subject id the adapter under test must map a conformance email to. */
export const credentialConformanceSubject = (email: Email): SubjectId =>
  decodeSubjectId(`subject:${email}`);

/**
 * `IdentityResolver` implementing the credential-conformance email mapping,
 * for adapters that resolve emails through the resolver.
 */
export const layerCredentialConformanceResolver: Layer.Layer<IdentityResolver> = Layer.succeed(
  IdentityResolver,
)({
  findByVerifiedEmail: (email) => Effect.succeed(Option.some(credentialConformanceSubject(email))),
});

const passwordHashOf = (name: string) => decodePasswordHash(`password-hash:${name}`);

const credentialLockOptions = { attemptLimit: 3, lockDuration: Duration.minutes(15) };

const credentialCase = <CaseError>(
  name: string,
  run: Effect.Effect<void, CaseError, PasswordCredentialStore>,
): PasswordCredentialStoreConformanceCase => ({ name, run: Effect.orDie(run) });

export const passwordCredentialStoreConformanceCases: ReadonlyArray<PasswordCredentialStoreConformanceCase> =
  [
    credentialCase(
      "upsert and find round-trip through subject and email",
      Effect.gen(function* () {
        const store = yield* PasswordCredentialStore;
        const email = emailOf("credential-roundtrip");
        const subjectId = credentialConformanceSubject(email);

        yield* store.upsert(subjectId, passwordHashOf("roundtrip"));
        const bySubject = yield* store.findBySubject(subjectId);

        yield* check(
          Option.isSome(bySubject) && bySubject.value.hash === passwordHashOf("roundtrip"),
          "findBySubject must return the upserted hash",
        );
        const byEmail = yield* store.findByEmail(email);

        yield* check(
          Option.isSome(byEmail) && byEmail.value.subjectId === subjectId,
          "findByEmail must resolve to the same credential",
        );
        yield* check(
          Option.isSome(byEmail) &&
            byEmail.value.failedAttempts === 0 &&
            Option.isNone(byEmail.value.lockedUntil),
          "a fresh credential must be unlocked with zero failures",
        );
      }),
    ),

    credentialCase(
      "failures count up and lock at the configured threshold",
      Effect.gen(function* () {
        const store = yield* PasswordCredentialStore;
        const email = emailOf("credential-lock");
        const subjectId = credentialConformanceSubject(email);

        yield* store.upsert(subjectId, passwordHashOf("lock"));
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        const beforeLock = yield* store.findByEmail(email);

        yield* check(
          Option.isSome(beforeLock) &&
            beforeLock.value.failedAttempts === 2 &&
            Option.isNone(beforeLock.value.lockedUntil),
          "failures below the limit must count without locking",
        );
        yield* store.recordFailure(subjectId, credentialLockOptions);
        const locked = yield* store.findByEmail(email);
        const now = yield* DateTime.now;

        yield* check(
          Option.isSome(locked) &&
            locked.value.failedAttempts === 3 &&
            Option.isSome(locked.value.lockedUntil) &&
            DateTime.toEpochMillis(locked.value.lockedUntil.value) > DateTime.toEpochMillis(now),
          "reaching the limit must set a lock in the future",
        );
      }),
    ),

    credentialCase(
      "success clears failures and the lock without touching the hash",
      Effect.gen(function* () {
        const store = yield* PasswordCredentialStore;
        const email = emailOf("credential-success");
        const subjectId = credentialConformanceSubject(email);

        yield* store.upsert(subjectId, passwordHashOf("success"));
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordSuccess(subjectId);
        const credential = yield* store.findByEmail(email);

        yield* check(
          Option.isSome(credential) &&
            credential.value.failedAttempts === 0 &&
            Option.isNone(credential.value.lockedUntil) &&
            credential.value.hash === passwordHashOf("success"),
          "recordSuccess must reset failures and the lock and keep the hash",
        );
      }),
    ),

    credentialCase(
      "upsert replaces the hash and clears failures and the lock",
      Effect.gen(function* () {
        const store = yield* PasswordCredentialStore;
        const email = emailOf("credential-upsert-reset");
        const subjectId = credentialConformanceSubject(email);

        yield* store.upsert(subjectId, passwordHashOf("before"));
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.upsert(subjectId, passwordHashOf("after"));
        const credential = yield* store.findByEmail(email);

        yield* check(
          Option.isSome(credential) &&
            credential.value.hash === passwordHashOf("after") &&
            credential.value.failedAttempts === 0 &&
            Option.isNone(credential.value.lockedUntil),
          "upsert must replace the hash and reset failures and the lock",
        );
      }),
    ),

    credentialCase(
      "an expired lock starts a fresh failure window",
      Effect.gen(function* () {
        const store = yield* PasswordCredentialStore;
        const email = emailOf("credential-lock-expiry");
        const subjectId = credentialConformanceSubject(email);

        yield* store.upsert(subjectId, passwordHashOf("lock-expiry"));
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        const locked = yield* store.findByEmail(email);

        yield* check(
          Option.isSome(locked) && Option.isSome(locked.value.lockedUntil),
          "reaching the limit must lock the credential",
        );
        yield* TestClock.adjust(credentialLockOptions.lockDuration);
        yield* store.recordFailure(subjectId, credentialLockOptions);
        const afterExpiry = yield* store.findByEmail(email);

        yield* check(
          Option.isSome(afterExpiry) &&
            afterExpiry.value.failedAttempts === 1 &&
            Option.isNone(afterExpiry.value.lockedUntil),
          "a failure after the lock expires must reset the count to one and not immediately re-lock",
        );
      }),
    ),

    credentialCase(
      "unknown subjects are no-ops",
      Effect.gen(function* () {
        const store = yield* PasswordCredentialStore;
        const email = emailOf("credential-unknown");
        const subjectId = credentialConformanceSubject(email);

        yield* store.recordFailure(subjectId, credentialLockOptions);
        yield* store.recordSuccess(subjectId);
        const credential = yield* store.findByEmail(email);

        yield* check(
          Option.isNone(credential),
          "failure and success accounting must ignore subjects without a credential",
        );
      }),
    ),
  ];
