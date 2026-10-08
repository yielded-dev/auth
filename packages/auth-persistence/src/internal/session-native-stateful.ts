import type { LifecycleHooks } from "@yielded/auth/Hooks";
import {
  SessionConflict,
  SessionInvalid,
  PendingAuthenticationInvalid,
  StaleAuthentication,
  SessionMetadata,
  SessionId,
  snapshotSessionAuthenticationProvenance,
  type StatefulSessionPersistence,
  type StatefulSessionRecord,
  type SessionRepository,
} from "@yielded/auth/Sessions";
import { DateTime, Effect, Option, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";
import type { Fragment } from "effect/sql/Statement";

import { sqlBatchAssertion } from "./d1-planning";
import { PersistenceMappingError, isMappedConstraintConflict } from "./mapping-error";
import type { StatefulSessionMapping } from "./models/session-model";
import type { NativeSqlTables } from "./native-sql-table";
import { sessionEvidenceDeadline } from "./session-native-authority";
import { makeNativeSessionPending, prepareNativeSession } from "./session-native-pending";
import {
  makeConditionalSqlInsert,
  makeNativeSessionRecords,
  sameSessionRecord,
} from "./session-native-record";
import {
  makeNativeSessionAuthorityState,
  sameSessionRevision,
  normalizeSessionOperation,
  sessionInvariant,
  sessionUnavailable,
} from "./session-native-state";
import { allocateSessionValue, preservesRevision } from "./session-policy";
import { exactSqlText, executeSqlChange } from "./sql-change";
import {
  CurrentSqlCommit,
  makeSqlCommitExecutor,
  SqlBatchCommit,
  appendSqlBatchStatement,
  registerSqlBatchPostcondition,
  registerSqlPostcondition,
} from "./sql-commit";
import type { AnyTableModel } from "./table-model";

export type NativeStatefulSessionMapping<Claims> = StatefulSessionMapping<
  Claims,
  AnyTableModel,
  AnyTableModel,
  AnyTableModel,
  AnyTableModel,
  unknown,
  unknown
>;

export const makeNativeStatefulSessionServices = Effect.fnUntraced(function* <Claims>(
  tables: NativeSqlTables,
  mapping: NativeStatefulSessionMapping<Claims>,
): Effect.fn.Return<
  {
    readonly statefulSessionPersistence: StatefulSessionPersistence<Claims>;
    readonly sessionRepository: SessionRepository;
  },
  never,
  SqlClient | LifecycleHooks | SqlBatchCommit
> {
  const batch = yield* SqlBatchCommit;

  const state = yield* makeNativeSessionAuthorityState(tables, mapping, batch !== undefined);
  const conditionalInsert = yield* makeConditionalSqlInsert();
  const records = yield* makeNativeSessionRecords(tables, mapping);
  const executor = yield* makeSqlCommitExecutor(sessionUnavailable);
  const external = yield* Effect.serviceOption(CurrentSqlCommit);

  const pending =
    mapping.pending === undefined
      ? undefined
      : yield* makeNativeSessionPending(
          tables,
          { ...mapping, ...mapping.pending },
          batch !== undefined,
        );

  const { sql, s, table, now, exact, live } = records;

  const native = <A, E, R>(
    work: Effect.Effect<A, E, R>,
    mode: "transaction" | "statement" = "transaction",
  ) =>
    batch === undefined
      ? executor.operation(normalizeSessionOperation(work), mode)
      : executor
          .operationBatch(normalizeSessionOperation(work))
          .pipe(Effect.provideService(SqlBatchCommit, batch));

  const stage = Effect.fnUntraced(function* (statement: Fragment, expected?: number) {
    if (batch !== undefined) {
      yield* appendSqlBatchStatement(sql`${statement}`);
      if (expected !== undefined)
        yield* appendSqlBatchStatement(sqlBatchAssertion(sql, sql`changes() = ${expected}`));

      return expected;
    }

    return yield* executeSqlChange(sql, statement);
  });

  const finalCondition = Effect.fnUntraced(function* (name: string, condition: Fragment) {
    if (batch !== undefined)
      yield* registerSqlBatchPostcondition({ name, statement: sqlBatchAssertion(sql, condition) });
    else if (Option.isSome(external))
      yield* registerSqlPostcondition({
        name,
        check: Effect.gen(function* () {
          const rows = yield* sql`select 1 where ${condition}`;

          sessionInvariant(rows.length === 1);
        }).pipe(
          Effect.mapError((cause) => PersistenceMappingError.make({ operation: "decode", cause })),
        ),
      });
  });

  const recordCondition = Effect.fnUntraced(function* (
    record: StatefulSessionRecord<Claims>,
    values: Readonly<Record<string, unknown>>,
  ) {
    return sql`exists(select 1 from ${table.name} where ${yield* records.owner(record)} and ${exact(table, s.securityRevision, record.securityRevision)} and ${records.millis(table, s.expiresAt)} = ${DateTime.toEpochMillis(record.expiresAt)} and ${records.millis(table, s.absoluteExpiresAt)} = ${DateTime.toEpochMillis(record.absoluteExpiresAt)} and ${records.encodedCondition(values)} and ${live(table)})`;
  });

  const classify = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.mapError((error) =>
        isMappedConstraintConflict(mapping.isConstraintConflict, error)
          ? SessionConflict.make({})
          : error,
      ),
    );

  const verify = Effect.fnUntraced(function* (digest: StatefulSessionRecord<Claims>["digest"]) {
    const subject = state.subject.as("verified_subject"),
      session = table.as("verified_session"),
      owner = mapping.subject;

    if (
      table.unencodedTextColumn?.(s.subjectId) !== undefined &&
      state.subject.unencodedTextColumn?.(owner.id) !== undefined
    ) {
      const rows =
        yield* sql`select ${session.fields("session_")}, ${subject.fields("subject_")} from ${session.name} join ${subject.name} on ${exactSqlText(sql, subject.column(owner.id), session.column(s.subjectId))} and ${state.activeSubject(subject)} and ${exactSqlText(sql, subject.column(owner.securityRevision), session.column(s.securityRevision))} where ${exact(session, s.digest, digest)} and ${live(session)} limit 2`;

      sessionInvariant(rows.length <= 1);
      if (rows[0] === undefined) return undefined;
      const record = yield* records.decode(session.decode(rows[0], "session_"));
      const decoded = subject.decode(rows[0], "subject_");

      sessionInvariant(
        (yield* mapping.subjectId.toSubject(decoded[owner.id])) === record.subjectId &&
          decoded[owner.securityRevision] === record.securityRevision &&
          owner.isActiveStatus(decoded[owner.status]),
      );

      return record;
    }
    const record = yield* records.read(digest);

    if (record === undefined) return undefined;
    const nativeSubject = yield* mapping.subjectId.toNative(record.subjectId);

    const rows =
      yield* sql`select ${subject.fields("subject_")} from ${subject.name} where ${state.id(subject, owner.id, nativeSubject)} and ${state.activeSubject(subject)} and ${state.exact(subject, owner.securityRevision, record.securityRevision)} and ${now} < ${DateTime.toEpochMillis(record.expiresAt)} limit 2`;

    sessionInvariant(rows.length <= 1);
    if (rows[0] === undefined) return undefined;
    sessionInvariant(
      (yield* mapping.subjectId.toSubject(subject.decode(rows[0], "subject_")[owner.id])) ===
        record.subjectId,
    );

    return record;
  });

  const persistence: StatefulSessionPersistence<Claims> = {
    establish: (input, project) =>
      native(
        classify(
          Effect.gen(function* () {
            const current = yield* state.read(input.evidence.revision.subjectId, true);

            if (
              current === undefined ||
              !sameSessionRevision(current.revision, input.evidence.revision)
            )
              return yield* StaleAuthentication.make({});

            const assessment = yield* sessionEvidenceDeadline(
              input.evidence,
              current.requirement,
              current.now,
            );

            const expires = DateTime.toEpochMillis(input.session.expiresAt),
              absolute = DateTime.toEpochMillis(input.session.absoluteExpiresAt);

            if (current.now >= expires || expires > absolute)
              return yield* StaleAuthentication.make({});
            let pendingExpiry = Infinity;

            if (input.pending !== undefined) {
              if (pending === undefined || mapping.pending === undefined)
                return yield* PendingAuthenticationInvalid.make({});
              const found = yield* pending.read("Login", input.pending.digest);

              if (
                found === undefined ||
                found.record.version !== input.pending.version ||
                found.record.subjectId !== current.revision.subjectId ||
                found.record.flowId !== input.pending.flowId ||
                found.record.bindingDigest !== input.pending.bindingDigest
              )
                return yield* PendingAuthenticationInvalid.make({});
              const original = yield* mapping.pending.login.decode(found.record.snapshot);

              if (
                original.digest !== input.pending.digest ||
                original.version !== input.pending.version ||
                !preservesRevision(input.evidence, original.evidence) ||
                DateTime.toEpochMillis(original.expiresAt) !== found.record.expiresAtMillis ||
                original.attemptLimit !== found.record.attemptLimit
              )
                return yield* PendingAuthenticationInvalid.make({});
              pendingExpiry = found.record.expiresAtMillis;
              yield* pending.consume("Login", input.pending, current.native);
            }

            const nativeSession = yield* allocateSessionValue(
              "interactive",
              s.allocateId,
              s.allocateIdSync,
            );

            const sessionId = yield* mapping.sessionId.toSession(nativeSession);

            if (sessionId === input.handoffSourceSessionId) return yield* SessionConflict.make({});

            const record: StatefulSessionRecord<Claims> = {
              ...input.session,
              sessionId,
              subjectId: current.revision.subjectId,
              securityRevision: current.revision.securityRevision,
              assurance:
                input.handoffSourceSessionId === undefined
                  ? assessment.assessed.assurance
                  : input.session.assurance,
              provenance: yield* snapshotSessionAuthenticationProvenance({
                evidence: input.evidence,
              }),
              issuedAt: DateTime.makeUnsafe(current.now),
            };

            const deadline = Math.min(expires, assessment.validUntil, pendingExpiry);

            yield* state.guardPolicy(current);
            const condition = sql`${state.authorityCondition(current.revision, current.native)} and ${now} >= ${current.now} and ${now} < ${deadline}`;

            const values = {
              ...s.encodeInsert(record, { subjectId: current.native, sessionId: nativeSession }),
              [s.sessionId]: nativeSession,
              [s.subjectId]: current.native,
              [s.digest]: record.digest,
              [s.securityRevision]: record.securityRevision,
              [s.issuedAt]: s.encodeInstant(record.issuedAt),
              [s.expiresAt]: s.encodeInstant(record.expiresAt),
              [s.absoluteExpiresAt]: s.encodeInstant(record.absoluteExpiresAt),
            };

            const changed = yield* stage(conditionalInsert(table, values, condition), 1);

            if (changed !== 1) return yield* StaleAuthentication.make({});
            const final = sql`${condition} and ${yield* recordCondition(record, values)}${input.pending === undefined || pending === undefined ? sql`` : sql` and ${pending.consumedCondition("Login", input.pending, current.native)}`}`;

            yield* finalCondition("stateful-session-issuance", final);
            if (batch === undefined && Option.isSome(external))
              yield* registerSqlPostcondition({
                name: "stateful-session-issued-metadata",
                check: Effect.gen(function* () {
                  const finalRecord = yield* records.read(record.digest);

                  sessionInvariant(
                    finalRecord !== undefined && sameSessionRecord(finalRecord, record),
                  );
                  const authority = yield* state.read(record.subjectId);

                  sessionInvariant(
                    authority !== undefined &&
                      sameSessionRevision(authority.revision, input.evidence.revision),
                  );
                  yield* sessionEvidenceDeadline(
                    input.evidence,
                    authority.requirement,
                    authority.now,
                  );
                }).pipe(
                  Effect.mapError((cause) =>
                    PersistenceMappingError.make({ operation: "decode", cause }),
                  ),
                ),
              });

            return yield* prepareNativeSession(record, project);
          }),
        ),
      ),
    verify: ({ digest }) =>
      executor
        .verify(verify(digest))
        .pipe(
          Effect.flatMap((record) =>
            record === undefined ? Effect.fail(SessionInvalid.make({})) : Effect.succeed(record),
          ),
        ),
    rotate: (input, project) =>
      native(
        classify(
          Effect.gen(function* () {
            const absolute = DateTime.toEpochMillis(input.record.absoluteExpiresAt),
              expires = DateTime.toEpochMillis(input.nextExpiresAt);

            if (
              expires > absolute ||
              input.nextDigest === input.record.digest ||
              input.nextCredentialVersion === input.record.credentialVersion
            )
              return yield* SessionConflict.make({});

            const needsSample =
              batch !== undefined ||
              sql.onDialectOrElse({ mysql: () => true, orElse: () => false });

            const sampled = needsSample
              ? Number((yield* sql`select ${now} as engine_now`)[0]?.engine_now)
              : DateTime.toEpochMillis(input.record.issuedAt);

            sessionInvariant(Number.isSafeInteger(sampled));

            const prepared = {
              ...input.record,
              digest: input.nextDigest,
              credentialVersion: input.nextCredentialVersion,
              expiresAt: input.nextExpiresAt,
              issuedAt: DateTime.makeUnsafe(sampled),
            };

            const values = {
              ...s.encodeRotation(prepared),
              [s.digest]: prepared.digest,
              [s.issuedAt]: tables.expression(mapping.clock.fromMillis(now)),
              [s.expiresAt]: s.encodeInstant(prepared.expiresAt),
            };

            const condition = sql`${yield* records.owner(input.record)} and ${live(table)} and ${now} < ${expires} and ${records.millis(table, s.absoluteExpiresAt)} = ${absolute}`;
            const update = sql`${table.update(values)} where ${condition}`;
            let record = prepared;

            if (needsSample) {
              // Batch receipts are prepared before execution. The exact sampled time is
              // written and checked; no speculative UPDATE result is treated as committed.
              const statement = sql`${table.update({ ...values, [s.issuedAt]: s.encodeInstant(prepared.issuedAt) })} where ${condition} and ${now} >= ${sampled}`;
              const changed = yield* stage(statement, 1);

              if (changed !== 1) return yield* SessionConflict.make({});
            } else {
              const rows = yield* sql`${update} returning ${table.fields("session_")}`;

              if (rows.length !== 1) return yield* SessionConflict.make({});
              record = yield* records.decode(table.decode(rows[0]!, "session_"));
            }
            yield* finalCondition(
              "stateful-session-rotation",
              yield* recordCondition(record, {
                ...values,
                [s.issuedAt]: s.encodeInstant(record.issuedAt),
              }),
            );

            return yield* prepareNativeSession(record, project);
          }),
        ),
        "statement",
      ),
    revokeDigest: (digest, project) =>
      native(
        Effect.gen(function* () {
          let expected: number | undefined;

          if (batch !== undefined)
            expected =
              (yield* sql`select 1 from ${table.name} where ${exact(table, s.digest, digest)} limit 2`)
                .length;

          const changed = yield* stage(
            sql`delete from ${table.name} where ${exact(table, s.digest, digest)}`,
            expected,
          );

          sessionInvariant(changed !== undefined && changed <= 1);
          yield* finalCondition(
            "stateful-session-digest-revocation",
            sql`not exists(select 1 from ${table.name} where ${exact(table, s.digest, digest)})`,
          );

          return yield* prepareNativeSession(changed === 1, project);
        }),
        "statement",
      ),
    revoke: (input, project) =>
      native(
        Effect.gen(function* () {
          const subject = yield* mapping.subjectId.toNative(input.subjectId),
            session = yield* mapping.sessionId.toNative(input.sessionId);

          const condition = sql`${state.id(table, s.subjectId, subject)} and ${state.id(table, s.sessionId, session)}`;

          yield* stage(sql`delete from ${table.name} where ${condition}`);
          yield* finalCondition(
            "stateful-session-revocation",
            sql`not exists(select 1 from ${table.name} where ${condition})`,
          );

          return yield* prepareNativeSession(undefined, project);
        }),
        "statement",
      ),
    revokeAll: (input, project) =>
      native(
        Effect.gen(function* () {
          const nativeSubject = yield* mapping.subjectId.toNative(input.subjectId),
            owner = mapping.subject;

          const next = yield* allocateSessionValue(
            "interactive",
            owner.nextSecurityRevision?.(input.expectedSecurityRevision),
            owner.nextSecurityRevisionSync === undefined
              ? undefined
              : () => owner.nextSecurityRevisionSync!(input.expectedSecurityRevision),
          );

          sessionInvariant(next !== input.expectedSecurityRevision);

          const changed = yield* stage(
            sql`${state.subject.update({ [owner.securityRevision]: next })} where ${state.id(state.subject, owner.id, nativeSubject)} and ${state.activeSubject(state.subject)} and ${state.exact(state.subject, owner.securityRevision, input.expectedSecurityRevision)}`,
            1,
          );

          if (changed !== 1) return yield* StaleAuthentication.make({});
          yield* finalCondition(
            "all-session-revocation",
            sql`exists(select 1 from ${state.subject.name} where ${state.id(state.subject, owner.id, nativeSubject)} and ${state.exact(state.subject, owner.securityRevision, next)})`,
          );

          return yield* prepareNativeSession(undefined, project);
        }),
        "statement",
      ),
  };

  const sessionRepository: SessionRepository = {
    list: (input) =>
      executor.read(
        Effect.gen(function* () {
          sessionInvariant(
            Number.isSafeInteger(input.limit) && input.limit > 0 && input.limit <= 1000,
          );

          const nativeSubject = yield* mapping.subjectId.toNative(input.subjectId),
            st = state.subject.as("listed_subject"),
            list = table.as("listed_session"),
            owner = mapping.subject;

          const cursor =
            input.cursor === undefined
              ? undefined
              : yield* mapping.sessionId.toNative(
                  yield* Schema.decodeEffect(SessionId)(input.cursor),
                );

          const rows =
            yield* sql`select ${list.fields("session_")}, ${st.fields("subject_")} from ${list.name} join ${st.name} on ${state.id(st, owner.id, nativeSubject)} and ${state.activeSubject(st)} and ${exactSqlText(sql, st.column(owner.securityRevision), list.column(s.securityRevision))} where ${state.id(list, s.subjectId, nativeSubject)} and ${live(list)}${cursor === undefined ? sql`` : sql` and ${list.column(s.sessionId)} > ${list.value(s.sessionId, cursor)}`} order by ${list.column(s.sessionId)} limit ${input.limit + 1}`;

          const decoded = yield* Effect.forEach(rows.slice(0, input.limit), (row) =>
            Effect.gen(function* () {
              const record = yield* records.decode(list.decode(row, "session_"));

              sessionInvariant(
                record.subjectId === input.subjectId &&
                  (yield* mapping.subjectId.toSubject(st.decode(row, "subject_")[owner.id])) ===
                    input.subjectId,
              );

              return yield* Schema.decodeEffect(Schema.toType(SessionMetadata))(record);
            }),
          );

          const nextCursor = rows.length > input.limit ? decoded.at(-1)?.sessionId : undefined;

          return { sessions: decoded, ...(nextCursor === undefined ? {} : { nextCursor }) };
        }),
      ),
  };

  return { statefulSessionPersistence: persistence, sessionRepository };
});
