import { Crypto, DateTime, Effect, Schema } from "effect";
import { Base64Url } from "effect/encoding";
import * as KeyValueStore from "effect/persistence/KeyValueStore";

import { coordinateCommit, hasCommitScope, type CommitJournal } from "../hooks/commit";
import { LifecycleHooks } from "../hooks/LifecycleHooks";
import { reportPersistenceFailure } from "../internal/diagnostics";
import { AtomicKeyValueStore } from "../key-value/AtomicKeyValueStore";
import { SubjectId } from "../Schema";
import { SessionConflict, SessionInvalid, SessionUnavailable, StaleAuthentication } from "./errors";
import { SecurityRevision, SessionId } from "./models";
import type { SignedSessionValidity } from "./persistence";

/** One authoritative subject aggregate, not a copy of session claims or user data.
 * Applications can keep credential revisions/pending consumption in authority so
 * their own AuthenticationAuthority commits against the same atomic record. */
export const KeyValueSessionSubject = Schema.Struct({
  subjectId: SubjectId,
  status: Schema.Literals(["active", "disabled"]),
  securityRevision: SecurityRevision,
  tombstones: Schema.Array(
    Schema.Struct({
      sessionId: SessionId,
      expiresAt: Schema.DateTimeUtcFromMillis,
    }),
  ).check(Schema.isMaxLength(10_000)),
  authority: Schema.Json,
});

export type KeyValueSessionSubject = typeof KeyValueSessionSubject.Type;

interface SubjectCommit<A> {
  readonly subject: KeyValueSessionSubject;
  readonly value: A;
  /** Approval requires the earliest issuance, proof and pending-state deadline.
   * The backend enforces it at the atomic write, including network delay.
   * Omit only for mutations that have no time-dependent authorization. */
  readonly expiresAt?: DateTime.Utc;
}

const Record = Schema.Struct({
  version: Schema.NonEmptyString,
  subject: KeyValueSessionSubject,
});

const RecordJson = Schema.fromJsonString(Record);
const decode = Schema.decodeEffect(RecordJson);
const encode = Schema.encodeEffect(RecordJson);

const normalizeStorageFailure = <A, E, R>(
  effect: Effect.Effect<A, E, R>,
): Effect.Effect<A, SessionUnavailable, R> =>
  reportPersistenceFailure(effect, () => false).pipe(
    Effect.mapError(() => SessionUnavailable.make({})),
  );

/** Application-owned identity and session state must share this subject authority.
 * SQL plus a KV mirror does not supply its atomic invalidation guarantee. */
export interface KeyValueSessionAuthority {
  readonly read: (
    subjectId: SubjectId,
  ) => Effect.Effect<KeyValueSessionSubject | undefined, SessionUnavailable>;
  /** One conditional commit; conflicts and unknown outcomes are never retried.
   * The callback may prepare receipts and update this aggregate only. It must not
   * issue credentials or perform writes in another store. Missing subjects must
   * be initialized by account provisioning, never from an incoming session. */
  readonly transact: <A, E, R>(
    subjectId: SubjectId,
    update: (
      current: KeyValueSessionSubject | undefined,
      journal: CommitJournal,
    ) => Effect.Effect<SubjectCommit<A>, E, R>,
  ) => Effect.Effect<A, E | SessionConflict | SessionUnavailable, R>;
}

export const makeKeyValueValidity = Effect.fnUntraced(function* (moduleId: string) {
  const store = yield* KeyValueStore.KeyValueStore;
  const atomic = yield* AtomicKeyValueStore;
  const crypto = yield* Crypto.Crypto;
  const hooks = yield* LifecycleHooks;
  const encoder = new TextEncoder();

  const key = (subjectId: SubjectId) =>
    `effect-auth:sessions:${encodeURIComponent(moduleId)}:subject:${encodeURIComponent(subjectId)}`;

  const readRecord = Effect.fnUntraced(function* (subjectId: SubjectId) {
    // One KV get contains both the subject marker and owner-scoped tombstones.
    const raw = yield* store.get(key(subjectId));

    if (raw === undefined) return { raw, subject: undefined };
    if (encoder.encode(raw).byteLength > 1_048_576) return yield* SessionUnavailable.make({});
    const record = yield* decode(raw);

    if (record.subject.subjectId !== subjectId) return yield* SessionUnavailable.make({});

    return { raw, subject: record.subject };
  }, normalizeStorageFailure);

  const transact: KeyValueSessionAuthority["transact"] = Effect.fnUntraced(function* <A, E, R>(
    subjectId: SubjectId,
    update: (
      current: KeyValueSessionSubject | undefined,
      journal: CommitJournal,
    ) => Effect.Effect<SubjectCommit<A>, E, R>,
  ) {
    if (yield* hasCommitScope) return yield* SessionUnavailable.make({});
    const current = yield* readRecord(subjectId);

    const commit = yield* coordinateCommit(
      Effect.fnUntraced(function* (journal) {
        const next = yield* update(current.subject, journal);

        if (next.subject.subjectId !== subjectId) return yield* SessionUnavailable.make({});
        const now = DateTime.toEpochMillis(yield* DateTime.now);

        const bytes = yield* crypto.randomBytes(32).pipe(normalizeStorageFailure);

        const raw = yield* encode({
          version: Base64Url.encode(bytes),
          subject: {
            ...next.subject,
            tombstones: next.subject.tombstones.filter(
              (entry) => DateTime.toEpochMillis(entry.expiresAt) > now,
            ),
          },
        }).pipe(normalizeStorageFailure);

        if (encoder.encode(raw).byteLength > 1_048_576) return yield* SessionUnavailable.make({});

        const committed = yield* atomic
          .compareAndSet(
            key(subjectId),
            current.raw,
            raw,
            next.expiresAt === undefined
              ? {}
              : { expiresAtMillis: DateTime.toEpochMillis(next.expiresAt) },
          )
          .pipe(normalizeStorageFailure);

        if (!committed) return yield* SessionConflict.make({});

        return next.value;
      }),
      { mode: "interactive" },
    ).pipe(
      Effect.provideService(LifecycleHooks, hooks),
      Effect.catchTag("HookConfigurationError", () => SessionUnavailable.make({})),
    );

    return commit.value;
  });

  const authority: KeyValueSessionAuthority = {
    read: (subjectId) => readRecord(subjectId).pipe(Effect.map((record) => record.subject)),
    transact,
  };

  const validity: SignedSessionValidity = {
    consistency: atomic.consistency,
    verify: Effect.fnUntraced(function* (session, now) {
      const subject = yield* authority.read(session.subjectId);

      if (
        subject === undefined ||
        subject.status !== "active" ||
        subject.securityRevision !== session.securityRevision ||
        subject.tombstones.some(
          (entry) =>
            entry.sessionId === session.sessionId &&
            DateTime.toEpochMillis(entry.expiresAt) > DateTime.toEpochMillis(now),
        )
      )
        return yield* SessionInvalid.make({});
    }),
    revoke: (input, prepare) =>
      transact(
        input.subjectId,
        Effect.fnUntraced(function* (subject, journal) {
          if (
            subject === undefined ||
            subject.status !== "active" ||
            subject.securityRevision !== input.expectedSecurityRevision
          )
            return yield* StaleAuthentication.make({});
          const previous = subject.tombstones.find((entry) => entry.sessionId === input.sessionId);

          return {
            subject: {
              ...subject,
              tombstones: [
                ...subject.tombstones.filter((entry) => entry.sessionId !== input.sessionId),
                {
                  sessionId: input.sessionId,
                  expiresAt: DateTime.makeUnsafe(
                    Math.max(
                      DateTime.toEpochMillis(input.absoluteExpiresAt),
                      previous === undefined ? 0 : DateTime.toEpochMillis(previous.expiresAt),
                    ),
                  ),
                },
              ],
            },
            value: prepare(undefined, journal),
          };
        }),
      ).pipe(Effect.catchTag("SessionConflict", () => StaleAuthentication.make({}))),
    revokeAll: (input, prepare) =>
      transact(
        input.subjectId,
        Effect.fnUntraced(function* (subject, journal) {
          if (
            subject === undefined ||
            subject.status !== "active" ||
            subject.securityRevision !== input.expectedSecurityRevision
          )
            return yield* StaleAuthentication.make({});

          const revision = yield* crypto.randomBytes(32).pipe(normalizeStorageFailure);

          return {
            subject: {
              ...subject,
              securityRevision: SecurityRevision.make(Base64Url.encode(revision)),
              tombstones: [],
            },
            value: prepare(undefined, journal),
          };
        }),
      ).pipe(Effect.catchTag("SessionConflict", () => StaleAuthentication.make({}))),
  };

  return { authority, validity };
});
