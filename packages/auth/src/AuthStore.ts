import { Context, DateTime, Duration, Effect, Layer, Schema, Semaphore } from "effect";

import { AuthRateLimited, AuthStoreError, InvalidRegistration } from "./Errors";
import {
  type ConsumeChallenge,
  type ConsumeRegistration,
  type TokenDigest,
  NewChallenge,
  NewRegistration,
  PendingRegistration,
  timingSafeStringEqual,
  VerifiedEmail,
} from "./Schema";

export type IssueChallengeError = AuthRateLimited | AuthStoreError;

export const EmailOtpRejectionReason = Schema.Literals([
  "missing_challenge",
  "consumed_challenge",
  "superseded_challenge",
  "expired_challenge",
  "missing_challenge_series",
  "attempts_exhausted",
  "bad_code",
]);

/** Internal rejection detail that the HTTP workflow collapses to `InvalidEmailOtp`. */
export class EmailOtpRejected extends Schema.TaggedError<EmailOtpRejected>()("EmailOtpRejected", {
  reason: EmailOtpRejectionReason,
}) {}

/**
 * Deliberately narrow storage driver behind the store state machine: the
 * in-memory map, Durable Object storage, or any keyed store whose writes
 * become visible in order. Values handed to `put` are already JSON-safe
 * encoded rows, so `get` legitimately yields `unknown`.
 * Retain challenge rows through their original expiry, including after consumption.
 */
export class AuthStoreBackend extends Context.Service<
  AuthStoreBackend,
  {
    /** Resolves the stored value for a key, or `undefined` when absent. */
    readonly get: (key: string) => Effect.Effect<unknown, AuthStoreError>;
    readonly put: (key: string, value: unknown) => Effect.Effect<void, AuthStoreError>;
    readonly remove: (key: string) => Effect.Effect<void, AuthStoreError>;
  }
>()("effect-auth/AuthStoreBackend") {
  /** In-memory backend for tests and local development; never durable. */
  static readonly layerMemory: Layer.Layer<AuthStoreBackend> = Layer.sync(AuthStoreBackend)(() => {
    const entries = new Map<string, unknown>();

    return AuthStoreBackend.of({
      get: (key) => Effect.sync(() => entries.get(key)),
      put: (key, value) =>
        Effect.sync(() => {
          entries.set(key, value);
        }),
      remove: (key) =>
        Effect.sync(() => {
          entries.delete(key);
        }),
    });
  });
}

// --- Stored rows ---------------------------------------------------------------

class StoredChallenge extends Schema.Class<StoredChallenge>("effect-auth/StoredChallenge")({
  challenge: NewChallenge,
  consumed: Schema.Boolean,
  superseded: Schema.Boolean,
}) {}

class StoredEmailSeries extends Schema.Class<StoredEmailSeries>("effect-auth/StoredEmailSeries")({
  activeChallengeKey: Schema.UndefinedOr(Schema.String),
  lastIssuedAt: Schema.DateTimeUtcFromMillis,
  rollingAttempts: Schema.Natural,
  windowExpiresAt: Schema.DateTimeUtcFromMillis,
}) {}

class StoredRegistration extends Schema.Class<StoredRegistration>("effect-auth/StoredRegistration")(
  {
    registration: NewRegistration,
    consumed: Schema.Boolean,
  },
) {}

// oxlint-disable-next-line no-restricted-properties -- AuthStoreBackend intentionally returns unknown persisted values.
const decodeChallengeRow = Schema.decodeUnknownEffect(StoredChallenge);
const encodeChallengeRow = Schema.encodeEffect(StoredChallenge);
// oxlint-disable-next-line no-restricted-properties -- AuthStoreBackend intentionally returns unknown persisted values.
const decodeSeriesRow = Schema.decodeUnknownEffect(StoredEmailSeries);
const encodeSeriesRow = Schema.encodeEffect(StoredEmailSeries);
// oxlint-disable-next-line no-restricted-properties -- AuthStoreBackend intentionally returns unknown persisted values.
const decodeRegistrationRow = Schema.decodeUnknownEffect(StoredRegistration);
const encodeRegistrationRow = Schema.encodeEffect(StoredRegistration);

const challengeKey = (tokenDigest: string) => `challenge:${tokenDigest}`;
const seriesKey = (purpose: string, email: string) => `series:${purpose}|${email}`;
const registrationKey = (tokenDigest: string) => `registration:${tokenDigest}`;

/**
 * The canonical store state machine over an `AuthStoreBackend`. Operations are
 * serialized through an internal semaphore, so the exactly-once consume
 * guarantees hold even when the backend's reads and writes suspend. Runtimes
 * that already serialize requests (a Durable Object's input gates) get a
 * second, redundant layer of protection.
 */
const makeBackendAuthStore = Effect.gen(function* () {
  const backend = yield* AuthStoreBackend;
  const semaphore = yield* Semaphore.make(1);
  const serialized = semaphore.withPermits(1);

  const read = <Row, DecodeError>(
    key: string,
    decode: (value: unknown) => Effect.Effect<Row, DecodeError>,
  ): Effect.Effect<Row | undefined, AuthStoreError> =>
    backend.get(key).pipe(
      Effect.mapError(() => AuthStoreError.make({ message: "Auth store read failed" })),
      Effect.flatMap((value) =>
        value === undefined
          ? // The absent row is a meaningful result, not a discarded void.
            // @effect-diagnostics-next-line effectSucceedWithVoid:off
            Effect.succeed(undefined)
          : decode(value).pipe(
              Effect.mapError(() => AuthStoreError.make({ message: "Corrupt auth store row" })),
            ),
      ),
    );

  const write = <Row, EncodeError>(
    key: string,
    encode: (row: Row) => Effect.Effect<unknown, EncodeError>,
    row: Row,
  ): Effect.Effect<void, AuthStoreError> =>
    encode(row).pipe(
      Effect.mapError(() => AuthStoreError.make({ message: "Auth store write failed" })),
      Effect.flatMap((value) =>
        backend
          .put(key, value)
          .pipe(Effect.mapError(() => AuthStoreError.make({ message: "Auth store write failed" }))),
      ),
    );

  const issueChallenge = Effect.fn("AuthStore.issueChallenge")(function* (input: NewChallenge) {
    const now = DateTime.toEpochMillis(yield* DateTime.now);
    const existing = yield* read(challengeKey(input.tokenDigest), decodeChallengeRow);

    // An issuance is immutable; a retry must not reset its terminal state.
    if (existing !== undefined) {
      return yield* AuthRateLimited.make({ retryAfterSeconds: 1 });
    }

    const key = seriesKey(input.purpose, input.email);
    const series = yield* read(key, decodeSeriesRow);
    const cooldownMillis = Duration.toMillis(input.resendCooldown);

    if (series !== undefined) {
      const lastIssuedAt = DateTime.toEpochMillis(series.lastIssuedAt);

      if (now < lastIssuedAt + cooldownMillis) {
        return yield* AuthRateLimited.make({
          retryAfterSeconds: Math.ceil((lastIssuedAt + cooldownMillis - now) / 1000),
        });
      }
      if (series.activeChallengeKey !== undefined) {
        const active = yield* read(series.activeChallengeKey, decodeChallengeRow);

        if (active !== undefined && !active.superseded) {
          yield* write(
            series.activeChallengeKey,
            encodeChallengeRow,
            StoredChallenge.make({ ...active, superseded: true }),
          );
        }
      }
    }

    // The rolling wrong-code budget survives resends and only resets once
    // the previous window has fully expired.
    const rollingAttempts =
      series !== undefined && now < DateTime.toEpochMillis(series.windowExpiresAt)
        ? series.rollingAttempts
        : 0;

    yield* write(
      challengeKey(input.tokenDigest),
      encodeChallengeRow,
      StoredChallenge.make({ challenge: input, consumed: false, superseded: false }),
    );
    yield* write(
      key,
      encodeSeriesRow,
      StoredEmailSeries.make({
        activeChallengeKey: challengeKey(input.tokenDigest),
        lastIssuedAt: yield* DateTime.now,
        rollingAttempts,
        windowExpiresAt: input.expiresAt,
      }),
    );
  });

  const consumeChallenge = Effect.fn("AuthStore.consumeChallenge")(function* (
    input: ConsumeChallenge,
  ) {
    const reject = (reason: typeof EmailOtpRejectionReason.Type) =>
      EmailOtpRejected.make({ reason });

    const now = DateTime.toEpochMillis(yield* DateTime.now);
    const row = yield* read(challengeKey(input.tokenDigest), decodeChallengeRow);

    if (row === undefined) {
      return yield* reject("missing_challenge");
    }
    const key = seriesKey(row.challenge.purpose, row.challenge.email);
    const series = yield* read(key, decodeSeriesRow);

    if (row.consumed) return yield* reject("consumed_challenge");
    if (row.superseded) return yield* reject("superseded_challenge");
    if (now >= DateTime.toEpochMillis(row.challenge.expiresAt)) {
      return yield* reject("expired_challenge");
    }
    if (series === undefined) return yield* reject("missing_challenge_series");
    if (series.rollingAttempts >= row.challenge.attemptLimit) {
      return yield* reject("attempts_exhausted");
    }
    const candidate = input.otpDigests[row.challenge.otpKeyId];

    const matches =
      candidate !== undefined && timingSafeStringEqual(candidate, row.challenge.otpDigest);

    if (!matches) {
      yield* write(
        key,
        encodeSeriesRow,
        StoredEmailSeries.make({ ...series, rollingAttempts: series.rollingAttempts + 1 }),
      );

      return yield* reject("bad_code");
    }
    yield* write(
      challengeKey(input.tokenDigest),
      encodeChallengeRow,
      StoredChallenge.make({ ...row, consumed: true }),
    );
    yield* backend
      .remove(key)
      .pipe(Effect.mapError(() => AuthStoreError.make({ message: "Auth store write failed" })));

    return VerifiedEmail.make({
      email: row.challenge.email,
      purpose: row.challenge.purpose,
    });
  });

  const issueRegistration = Effect.fn("AuthStore.issueRegistration")(function* (
    input: NewRegistration,
  ) {
    yield* write(
      registrationKey(input.tokenDigest),
      encodeRegistrationRow,
      StoredRegistration.make({ registration: input, consumed: false }),
    );
  });

  const inspectRegistration = Effect.fn("AuthStore.inspectRegistration")(function* (
    tokenDigest: TokenDigest,
  ) {
    const now = DateTime.toEpochMillis(yield* DateTime.now);
    const row = yield* read(registrationKey(tokenDigest), decodeRegistrationRow);

    if (
      row === undefined ||
      row.consumed ||
      now >= DateTime.toEpochMillis(row.registration.expiresAt)
    ) {
      return yield* InvalidRegistration.make();
    }

    return PendingRegistration.make({
      registrationId: row.registration.registrationId,
      email: row.registration.email,
      purpose: row.registration.purpose,
      issuedAt: row.registration.issuedAt,
      expiresAt: row.registration.expiresAt,
    });
  });

  const consumeRegistration = Effect.fn("AuthStore.consumeRegistration")(function* (
    input: ConsumeRegistration,
  ) {
    const now = DateTime.toEpochMillis(yield* DateTime.now);
    const row = yield* read(registrationKey(input.tokenDigest), decodeRegistrationRow);

    if (
      row === undefined ||
      row.consumed ||
      now >= DateTime.toEpochMillis(row.registration.expiresAt)
    ) {
      return yield* InvalidRegistration.make();
    }
    yield* write(
      registrationKey(input.tokenDigest),
      encodeRegistrationRow,
      StoredRegistration.make({ ...row, consumed: true }),
    );
  });

  return {
    issueChallenge: (input: NewChallenge) => serialized(issueChallenge(input)),
    consumeChallenge: (input: ConsumeChallenge) => serialized(consumeChallenge(input)),
    issueRegistration: (input: NewRegistration) => serialized(issueRegistration(input)),
    inspectRegistration: (tokenDigest: TokenDigest) => serialized(inspectRegistration(tokenDigest)),
    consumeRegistration: (input: ConsumeRegistration) => serialized(consumeRegistration(input)),
  };
});

/**
 * Semantic persistence port for challenges and pending registrations, not
 * CRUD. The consume operations must be atomic: exactly one of concurrent
 * valid consumptions may succeed. Per-challenge attempts, resend cooldown,
 * and email-scoped issuance limits live behind this contract; IP/network
 * limits stay at the edge.
 *
 * Adapters either implement this interface directly against a store with real
 * transactions, or provide an `AuthStoreBackend` to `layerBackend`. Either
 * way, the conformance suite exported from `effect-auth/Testing` is the
 * acceptance test.
 */
export class AuthStore extends Context.Service<
  AuthStore,
  {
    readonly issueChallenge: (input: NewChallenge) => Effect.Effect<void, IssueChallengeError>;
    /**
     * Checks token digest, OTP digest, purpose, expiry, supersession,
     * consumption, and attempt budget as one atomic operation. A failed
     * comparison increments the rolling attempt budget; success consumes the
     * challenge. The workflow logs the internal rejection reason, then
     * collapses every failure to the public `InvalidEmailOtp`.
     */
    readonly consumeChallenge: (
      input: ConsumeChallenge,
    ) => Effect.Effect<VerifiedEmail, EmailOtpRejected | AuthStoreError>;
    readonly issueRegistration: (input: NewRegistration) => Effect.Effect<void, AuthStoreError>;
    readonly inspectRegistration: (
      tokenDigest: TokenDigest,
    ) => Effect.Effect<PendingRegistration, InvalidRegistration | AuthStoreError>;
    readonly consumeRegistration: (
      input: ConsumeRegistration,
    ) => Effect.Effect<void, InvalidRegistration | AuthStoreError>;
  }
>()("effect-auth/AuthStore") {
  /** The canonical state machine over whichever `AuthStoreBackend` is provided. */
  static readonly layerBackend: Layer.Layer<AuthStore, never, AuthStoreBackend> =
    Layer.effect(AuthStore)(makeBackendAuthStore);

  /**
   * In-memory adapter for tests and local development. Never a durable
   * production adapter.
   */
  static readonly layerMemory: Layer.Layer<AuthStore> = AuthStore.layerBackend.pipe(
    Layer.provide(AuthStoreBackend.layerMemory),
  );
}

export { AuthStoreDecisions, type ChallengeConsumeDecision } from "./internal/AuthStoreDecisions";
export type { ConsumeDecision } from "./auth/ConsumeDecision";
