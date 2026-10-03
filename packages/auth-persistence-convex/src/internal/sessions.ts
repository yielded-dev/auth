import { SubjectId, TokenDigest } from "@yielded/auth/Schema";
import * as Sessions from "@yielded/auth/Sessions";
import { Context, DateTime, Effect, Layer, Schema } from "effect";

import { DocumentStore, Transaction, type Codec } from "./documents";
import {
  activeSubject,
  currentRevision,
  evidenceCurrent,
  identityPartitions,
  invalidateSubject,
  Subject,
  subjectKey,
  tupleKey,
} from "./identity";

const Flow = Schema.Struct({
  flowId: Sessions.AuthenticationFlowId,
  subjectId: SubjectId,
  state: Schema.Literals(["Pending", "Established"]),
  pendingDigest: Schema.optionalKey(TokenDigest),
  dedupUntil: Schema.Int,
});

/** Claims remain encoded so additional-factor context never decodes application claims. */
const Pending = Schema.Struct({
  digest: TokenDigest,
  version: Sessions.SecurityRevision,
  evidence: Sessions.AuthenticationEvidence,
  expiresAt: Schema.DateTimeUtcFromMillis,
  attemptLimit: Schema.Int.check(Schema.isGreaterThan(0)),
  failedAttempts: Schema.Natural,
  consumed: Schema.Boolean,
  claimsJson: Schema.String,
});

const Digest = Schema.Struct({ sessionId: Sessions.SessionId, subjectId: SubjectId });
const Tombstone = Schema.Struct({ absoluteExpiresAt: Schema.DateTimeUtcFromMillis });
const ListLimit = Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 100 }));

export const sessionPartitions = (moduleId: string) => ({
  records: tupleKey("sessions/records", moduleId),
  digests: tupleKey("sessions/digests", moduleId),
  flows: tupleKey("sessions/flows", moduleId),
  pending: tupleKey("sessions/pending", moduleId),
  owner: (subjectId: string) => tupleKey("sessions/owner", moduleId, subjectId),
  tombstones: (subjectId: string) => tupleKey("sessions/tombstones", moduleId, subjectId),
});

export interface SessionDefinition<Claims, Stateful, Repository, PendingId, Signed> {
  readonly moduleId: string;
  readonly StatefulSessionPersistence: Context.Key<
    Stateful,
    Sessions.StatefulSessionPersistence<Claims>
  >;
  readonly SessionRepository: Context.Key<Repository, Sessions.SessionRepository>;
  readonly PendingAuthentication: Context.Key<PendingId, Sessions.PendingAuthentication<Claims>>;
  readonly SignedSessionValidity: Context.Key<Signed, Sessions.SignedSessionValidity>;
}

const metadata = (record: Sessions.SessionMetadata): Sessions.SessionMetadata => ({
  sessionId: record.sessionId,
  subjectId: record.subjectId,
  securityRevision: record.securityRevision,
  assurance: record.assurance,
  issuedAt: record.issuedAt,
  expiresAt: record.expiresAt,
  absoluteExpiresAt: record.absoluteExpiresAt,
});

const preservesEvidence = (
  completed: Sessions.AuthenticationEvidence,
  original: Sessions.AuthenticationEvidence,
) =>
  completed.flowId === original.flowId &&
  completed.bindingDigest === original.bindingDigest &&
  completed.revision.subjectId === original.revision.subjectId &&
  completed.revision.securityRevision === original.revision.securityRevision &&
  original.revision.credentials.every((expected) =>
    completed.revision.credentials.some(
      (actual) =>
        actual.credentialId === expected.credentialId && actual.revision === expected.revision,
    ),
  ) &&
  original.proofs.every((expected) =>
    completed.proofs.some(
      (actual) =>
        actual.method === expected.method &&
        actual.credentialId === expected.credentialId &&
        actual.userVerified === expected.userVerified &&
        actual.phishingResistant === expected.phishingResistant &&
        DateTime.toEpochMillis(actual.verifiedAt) === DateTime.toEpochMillis(expected.verifiedAt) &&
        actual.factors.length === expected.factors.length &&
        actual.factors.every((factor, index) => factor === expected.factors[index]),
    ),
  );

/** All services share one namespace and identity authority. Each operation owns one
 * optimistic document commit; application callbacks and credential preparation stay in the action.
 */
export const makeSessions = <Claims extends Codec, Stateful, Repository, PendingId, Signed>(
  claims: Claims,
  definition: SessionDefinition<Claims["Type"], Stateful, Repository, PendingId, Signed>,
) =>
  Layer.effectContext(
    Effect.gen(function* () {
      const store = yield* DocumentStore;
      const partitions = sessionPartitions(definition.moduleId);
      const ClaimsCodec: Schema.Codec<Claims["Type"], Claims["Encoded"]> = claims;

      const Record = Schema.Struct({
        ...Sessions.SessionMetadata.fields,
        claims: ClaimsCodec,
        digest: TokenDigest,
        version: Sessions.SecurityRevision,
        provenance: Sessions.SessionAuthenticationProvenance,
        credentialVersion: Sessions.SessionCredentialVersion,
      });

      const claimsJson = Schema.fromJsonString(ClaimsCodec);

      const owned = <A, E>(body: Effect.Effect<A, E, Transaction>) =>
        store
          .transaction(body)
          .pipe(
            Effect.catchTag(["ConvexPersistenceUnavailable", "ConvexTransactionConflict"], () =>
              Sessions.SessionUnavailable.make({}),
            ),
          );

      const raced = <A, E>(body: Effect.Effect<A, E, Transaction>) =>
        store.transaction(body).pipe(
          Effect.catchTag("ConvexPersistenceUnavailable", () =>
            Sessions.SessionUnavailable.make({}),
          ),
          Effect.catchTag("ConvexTransactionConflict", () => Sessions.SessionConflict.make({})),
        );

      const readPending = Effect.fnUntraced(function* (
        digest: TokenDigest,
        bindingDigest?: TokenDigest,
      ) {
        const tx = yield* Transaction;
        const row = yield* tx.get(Pending, partitions.pending, digest);

        if (
          row === undefined ||
          row.digest !== digest ||
          row.consumed ||
          row.failedAttempts >= row.attemptLimit ||
          (bindingDigest !== undefined && row.evidence.bindingDigest !== bindingDigest) ||
          tx.now >= DateTime.toEpochMillis(row.expiresAt)
        )
          return yield* Sessions.PendingAuthenticationInvalid.make({});
        const flow = yield* tx.get(Flow, partitions.flows, row.evidence.flowId);

        if (
          flow === undefined ||
          flow.state !== "Pending" ||
          flow.pendingDigest !== digest ||
          flow.flowId !== row.evidence.flowId ||
          flow.subjectId !== row.evidence.revision.subjectId ||
          flow.dedupUntil <= tx.now
        )
          return yield* Sessions.PendingAuthenticationInvalid.make({});
        yield* evidenceCurrent(row.evidence).pipe(
          Effect.catchTag("StaleAuthentication", () =>
            Sessions.PendingAuthenticationInvalid.make({}),
          ),
        );
        yield* tx.before(Math.min(DateTime.toEpochMillis(row.expiresAt), flow.dedupUntil));

        return row;
      });

      const availableFlow = Effect.fnUntraced(function* (flowId: Sessions.AuthenticationFlowId) {
        const tx = yield* Transaction;
        const existing = yield* tx.get(Flow, partitions.flows, flowId);

        if (existing !== undefined) {
          if (existing.flowId !== flowId) return yield* Sessions.SessionUnavailable.make({});
          if (existing.dedupUntil > tx.now) return yield* Sessions.SessionConflict.make({});
          if (existing.pendingDigest !== undefined) {
            const pending = yield* tx.get(Pending, partitions.pending, existing.pendingDigest);

            if (
              pending !== undefined &&
              (pending.digest !== existing.pendingDigest ||
                pending.evidence.flowId !== flowId ||
                pending.evidence.revision.subjectId !== existing.subjectId)
            )
              return yield* Sessions.SessionUnavailable.make({});
            yield* tx.remove(partitions.pending, existing.pendingDigest);
          }
        }
      });

      const establishFlow = Effect.fnUntraced(function* (
        evidence: Sessions.AuthenticationEvidence,
        until: DateTime.Utc,
        pending?: Sessions.PendingConsumption,
      ) {
        const tx = yield* Transaction;

        if (pending === undefined) yield* availableFlow(evidence.flowId);
        else {
          const row = yield* readPending(pending.digest, pending.bindingDigest);

          if (
            row.version !== pending.version ||
            row.evidence.flowId !== pending.flowId ||
            !preservesEvidence(evidence, row.evidence)
          )
            return yield* Sessions.PendingAuthenticationInvalid.make({});
          yield* tx.put(Pending, partitions.pending, pending.digest, { ...row, consumed: true });
        }
        yield* tx.put(Flow, partitions.flows, evidence.flowId, {
          flowId: evidence.flowId,
          subjectId: evidence.revision.subjectId,
          state: "Established",
          dedupUntil: DateTime.toEpochMillis(until),
        });
      });

      const activeRevision = Effect.fnUntraced(function* (
        subjectId: SubjectId,
        revision: Sessions.SecurityRevision,
      ) {
        const subject = yield* activeSubject(subjectId);

        if (subject.securityRevision !== revision)
          return yield* Sessions.StaleAuthentication.make({});

        return subject;
      });

      const liveSession = Effect.fnUntraced(function* (record: Sessions.SessionMetadata) {
        const tx = yield* Transaction;

        yield* activeRevision(record.subjectId, record.securityRevision).pipe(
          Effect.catchTag("StaleAuthentication", () => Sessions.SessionInvalid.make({})),
        );
        const expiresAt = DateTime.toEpochMillis(record.expiresAt);
        const absoluteExpiresAt = DateTime.toEpochMillis(record.absoluteExpiresAt);

        if (
          tx.now >= expiresAt ||
          expiresAt > absoluteExpiresAt ||
          DateTime.toEpochMillis(record.issuedAt) > tx.now ||
          DateTime.toEpochMillis(record.assurance.authenticatedAt) >
            DateTime.toEpochMillis(record.issuedAt)
        )
          return yield* Sessions.SessionInvalid.make({});
        yield* tx.before(Math.min(expiresAt, absoluteExpiresAt));
      });

      const writeSession = Effect.fnUntraced(function* (
        record: Sessions.StatefulSessionRecord<Claims["Type"]>,
      ) {
        const tx = yield* Transaction;

        yield* tx.put(Record, partitions.records, record.sessionId, record);
        yield* tx.put(Digest, partitions.digests, record.digest, {
          sessionId: record.sessionId,
          subjectId: record.subjectId,
        });
        yield* tx.put(
          Sessions.SessionMetadata,
          partitions.owner(record.subjectId),
          record.sessionId,
          metadata(record),
        );
      });

      const removeSession = Effect.fnUntraced(function* (
        record: Sessions.StatefulSessionRecord<Claims["Type"]>,
      ) {
        const tx = yield* Transaction;
        const locator = yield* tx.get(Digest, partitions.digests, record.digest);

        if (
          locator === undefined ||
          locator.sessionId !== record.sessionId ||
          locator.subjectId !== record.subjectId
        )
          return yield* Sessions.SessionUnavailable.make({});
        yield* tx.remove(partitions.records, record.sessionId);
        yield* tx.remove(partitions.digests, record.digest);
        yield* tx.remove(partitions.owner(record.subjectId), record.sessionId);
      });

      const revokeAll: Sessions.StatefulSessionPersistence<Claims["Type"]>["revokeAll"] = (
        input,
        prepare,
      ) =>
        owned(
          Effect.gen(function* () {
            const tx = yield* Transaction;

            yield* invalidateSubject(input.subjectId, input.expectedSecurityRevision);

            return prepare(undefined, tx.journal);
          }),
        );

      const authority = Sessions.AuthenticationAuthority.of({
        capture: (subjectId, credentialIds) => owned(currentRevision(subjectId, credentialIds)),
        requirements: (evidence) =>
          owned(evidenceCurrent(evidence).pipe(Effect.map((result) => result.requirement))),
        approve: (input, prepare) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const current = yield* evidenceCurrent(input.evidence);

              if (
                !current.assessment.satisfied ||
                tx.now >= DateTime.toEpochMillis(input.expiresAt) ||
                DateTime.toEpochMillis(input.expiresAt) >
                  DateTime.toEpochMillis(input.absoluteExpiresAt)
              )
                return yield* Sessions.StaleAuthentication.make({});
              yield* tx.before(DateTime.toEpochMillis(input.expiresAt));
              yield* establishFlow(input.evidence, input.absoluteExpiresAt, input.pending).pipe(
                Effect.catchTag("SessionConflict", () => Sessions.StaleAuthentication.make({})),
              );

              return prepare(undefined, tx.journal);
            }),
          ),
      });

      const persistence: Sessions.StatefulSessionPersistence<Claims["Type"]> = {
        establish: (input, prepare) =>
          raced(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const current = yield* evidenceCurrent(input.evidence);
              const expiresAt = DateTime.toEpochMillis(input.session.expiresAt);

              if (
                !current.assessment.satisfied ||
                tx.now >= expiresAt ||
                expiresAt > DateTime.toEpochMillis(input.session.absoluteExpiresAt) ||
                input.session.subjectId !== input.evidence.revision.subjectId ||
                input.session.securityRevision !== input.evidence.revision.securityRevision
              )
                return yield* Sessions.StaleAuthentication.make({});
              yield* tx.before(expiresAt);
              if ((yield* tx.get(Digest, partitions.digests, input.session.digest)) !== undefined)
                return yield* Sessions.SessionConflict.make({});
              const sessionId = Sessions.SessionId.make(yield* tx.id);

              if ((yield* tx.get(Record, partitions.records, sessionId)) !== undefined)
                return yield* Sessions.SessionConflict.make({});

              const record: Sessions.StatefulSessionRecord<Claims["Type"]> = {
                ...input.session,
                sessionId,
                version: Sessions.SecurityRevision.make(yield* tx.id),
                assurance: current.assessment.assurance,
                provenance: yield* Sessions.snapshotSessionAuthenticationProvenance({
                  evidence: input.evidence,
                }),
                issuedAt: DateTime.makeUnsafe(tx.now),
              };

              const receipt = prepare(record, tx.journal);

              yield* establishFlow(input.evidence, input.session.absoluteExpiresAt, input.pending);
              yield* writeSession(record);

              return receipt;
            }),
          ),
        verify: (input) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const locator = yield* tx.get(Digest, partitions.digests, input.digest);

              if (locator === undefined) return yield* Sessions.SessionInvalid.make({});
              const record = yield* tx.get(Record, partitions.records, locator.sessionId);

              if (
                record === undefined ||
                record.digest !== input.digest ||
                record.sessionId !== locator.sessionId ||
                record.subjectId !== locator.subjectId
              )
                return yield* Sessions.SessionInvalid.make({});
              yield* liveSession(record);

              return record;
            }),
          ),
        rotate: (input, prepare) =>
          raced(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const record = yield* tx.get(Record, partitions.records, input.sessionId);

              if (
                record === undefined ||
                record.sessionId !== input.sessionId ||
                record.digest !== input.expectedDigest ||
                record.version !== input.expectedVersion ||
                record.securityRevision !== input.expectedSecurityRevision ||
                input.nextDigest === record.digest ||
                input.nextCredentialVersion === record.credentialVersion ||
                DateTime.toEpochMillis(input.nextExpiresAt) <= tx.now ||
                DateTime.toEpochMillis(input.nextExpiresAt) >
                  DateTime.toEpochMillis(record.absoluteExpiresAt)
              )
                return yield* Sessions.SessionConflict.make({});
              yield* liveSession(record);
              const locator = yield* tx.get(Digest, partitions.digests, record.digest);

              if (
                locator === undefined ||
                locator.sessionId !== record.sessionId ||
                locator.subjectId !== record.subjectId ||
                (yield* tx.get(Digest, partitions.digests, input.nextDigest)) !== undefined
              )
                return yield* Sessions.SessionConflict.make({});
              yield* tx.before(DateTime.toEpochMillis(input.nextExpiresAt));

              const next: Sessions.StatefulSessionRecord<Claims["Type"]> = {
                ...record,
                digest: input.nextDigest,
                credentialVersion: input.nextCredentialVersion,
                version: Sessions.SecurityRevision.make(yield* tx.id),
                issuedAt: DateTime.makeUnsafe(tx.now),
                expiresAt: input.nextExpiresAt,
              };

              const receipt = prepare(next, tx.journal);

              yield* tx.remove(partitions.digests, record.digest);
              yield* writeSession(next);

              return receipt;
            }),
          ),
        revokeDigest: (digest, prepare) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const locator = yield* tx.get(Digest, partitions.digests, digest);

              if (locator === undefined) return prepare(false, tx.journal);
              const record = yield* tx.get(Record, partitions.records, locator.sessionId);

              if (
                record === undefined ||
                record.digest !== digest ||
                record.sessionId !== locator.sessionId ||
                record.subjectId !== locator.subjectId
              )
                return yield* Sessions.SessionUnavailable.make({});
              const receipt = prepare(true, tx.journal);

              yield* removeSession(record);

              return receipt;
            }),
          ),
        revoke: (input, prepare) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              yield* activeRevision(input.subjectId, input.expectedSecurityRevision);
              const record = yield* tx.get(Record, partitions.records, input.sessionId);
              const receipt = prepare(undefined, tx.journal);

              if (record !== undefined && record.subjectId === input.subjectId) {
                if (record.sessionId !== input.sessionId)
                  return yield* Sessions.SessionUnavailable.make({});
                yield* removeSession(record);
              }

              return receipt;
            }),
          ),
        revokeAll,
      };

      const repository: Sessions.SessionRepository = {
        list: (input) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              const limit = yield* Schema.decodeEffect(ListLimit)(input.limit).pipe(
                Effect.mapError(() => Sessions.SessionUnavailable.make({})),
              );

              const subject = yield* tx.get(
                Subject,
                identityPartitions.subjects,
                subjectKey(input.subjectId),
              );

              if (subject === undefined || !subject.active) return { sessions: [] };
              if (subject.subjectId !== input.subjectId)
                return yield* Sessions.SessionUnavailable.make({});

              const rows = yield* tx.scan(
                Sessions.SessionMetadata,
                partitions.owner(input.subjectId),
                {
                  ...(input.cursor === undefined ? {} : { after: input.cursor }),
                  limit: limit + 1,
                },
              );

              const page = rows.slice(0, limit);
              const sessions: Sessions.SessionMetadata[] = [];

              for (const row of page) {
                if (row.value.sessionId !== row.key || row.value.subjectId !== input.subjectId)
                  return yield* Sessions.SessionUnavailable.make({});
                if (
                  row.value.securityRevision !== subject.securityRevision ||
                  DateTime.toEpochMillis(row.value.expiresAt) <= tx.now ||
                  DateTime.toEpochMillis(row.value.absoluteExpiresAt) <= tx.now
                )
                  continue;
                yield* tx.before(
                  Math.min(
                    DateTime.toEpochMillis(row.value.expiresAt),
                    DateTime.toEpochMillis(row.value.absoluteExpiresAt),
                  ),
                );
                sessions.push(metadata(row.value));
              }
              const last = page[page.length - 1];

              return {
                sessions,
                ...(rows.length > page.length && last !== undefined
                  ? { nextCursor: last.key }
                  : {}),
              };
            }),
          ),
      };

      const pending: Sessions.PendingAuthentication<Claims["Type"]> = {
        create: (input, _now, prepare) =>
          raced(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              yield* evidenceCurrent(input.evidence);
              if (DateTime.toEpochMillis(input.expiresAt) <= tx.now)
                return yield* Sessions.StaleAuthentication.make({});
              yield* tx.before(DateTime.toEpochMillis(input.expiresAt));
              yield* availableFlow(input.evidence.flowId);
              if ((yield* tx.get(Pending, partitions.pending, input.digest)) !== undefined)
                return yield* Sessions.SessionConflict.make({});

              const record: Sessions.PendingAuthenticationRecord<Claims["Type"]> = {
                ...input,
                version: Sessions.SecurityRevision.make(yield* tx.id),
              };

              const encodedClaims = yield* Schema.encodeEffect(claimsJson)(input.claims).pipe(
                Effect.mapError(() => Sessions.SessionUnavailable.make({})),
              );

              const receipt = prepare(record, tx.journal);

              yield* tx.put(Pending, partitions.pending, input.digest, {
                digest: record.digest,
                version: record.version,
                evidence: record.evidence,
                expiresAt: record.expiresAt,
                attemptLimit: record.attemptLimit,
                failedAttempts: 0,
                consumed: false,
                claimsJson: encodedClaims,
              });
              yield* tx.put(Flow, partitions.flows, input.evidence.flowId, {
                flowId: input.evidence.flowId,
                subjectId: input.evidence.revision.subjectId,
                state: "Pending",
                pendingDigest: input.digest,
                dedupUntil: DateTime.toEpochMillis(input.expiresAt),
              });

              return receipt;
            }),
          ),
        context: (input) =>
          owned(
            readPending(input.digest).pipe(Effect.flatMap(Sessions.pendingAuthenticationContext)),
          ),
        read: (input) =>
          owned(
            Effect.gen(function* () {
              const row = yield* readPending(input.digest, input.bindingDigest);

              const decodedClaims = yield* Schema.decodeEffect(claimsJson)(row.claimsJson).pipe(
                Effect.mapError(() => Sessions.SessionUnavailable.make({})),
              );

              return {
                digest: row.digest,
                version: row.version,
                evidence: row.evidence,
                expiresAt: row.expiresAt,
                attemptLimit: row.attemptLimit,
                claims: decodedClaims,
              };
            }),
          ),
        reject: (input, prepare) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              const row = yield* readPending(input.digest, input.bindingDigest).pipe(
                Effect.catchTag("PendingAuthenticationInvalid", () => Effect.void),
              );

              const receipt = prepare({ _tag: "Rejected" }, tx.journal);

              if (row !== undefined)
                yield* tx.put(Pending, partitions.pending, input.digest, {
                  ...row,
                  failedAttempts: Math.min(row.attemptLimit, row.failedAttempts + 1),
                });

              return receipt;
            }),
          ),
      };

      const signed: Sessions.SignedSessionValidity = {
        verify: (session) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              yield* liveSession(session);

              const tombstone = yield* tx.get(
                Tombstone,
                partitions.tombstones(session.subjectId),
                session.sessionId,
              );

              if (
                tombstone !== undefined &&
                DateTime.toEpochMillis(tombstone.absoluteExpiresAt) > tx.now
              )
                return yield* Sessions.SessionInvalid.make({});
            }),
          ),
        revoke: (input, prepare) =>
          owned(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              yield* activeRevision(input.subjectId, input.expectedSecurityRevision);
              const partition = partitions.tombstones(input.subjectId);
              const previous = yield* tx.get(Tombstone, partition, input.sessionId);
              const receipt = prepare(undefined, tx.journal);

              if (
                previous === undefined ||
                DateTime.toEpochMillis(previous.absoluteExpiresAt) <
                  DateTime.toEpochMillis(input.absoluteExpiresAt)
              )
                yield* tx.put(Tombstone, partition, input.sessionId, {
                  absoluteExpiresAt: input.absoluteExpiresAt,
                });

              return receipt;
            }),
          ),
        revokeAll,
      };

      return Context.make(Sessions.AuthenticationAuthority, authority).pipe(
        Context.add(definition.StatefulSessionPersistence, persistence),
        Context.add(definition.SessionRepository, repository),
        Context.add(definition.PendingAuthentication, pending),
        Context.add(definition.SignedSessionValidity, signed),
      );
    }),
  );
