import { CurrentCommitJournal, type PreparedCommit, type CommitJournal } from "@yielded/auth/Hooks";
import { SubjectId, TokenDigest } from "@yielded/auth/Schema";
import {
  AuthenticationFlowId,
  SecurityRevision,
  type PendingConsumption,
} from "@yielded/auth/Sessions";
import { Effect, Schema } from "effect";
import { SqlClient } from "effect/sql/SqlClient";
import type { Fragment } from "effect/sql/Statement";

import { sqlBatchAssertion } from "./d1-planning";
import type { SubjectIdCodec } from "./models/common";
import type {
  SessionPendingTables,
  SessionExecution,
  SessionPendingInsert,
} from "./models/session-model";
import type { NativeSqlTables, SqlTable } from "./native-sql-table";
import { conditionalSqlInsert } from "./session-native-record";
import { sessionInvariant } from "./session-native-state";
import { exactSqlText, executeSqlChange } from "./sql-change";
import { appendSqlBatchStatement, CurrentSqlCommit, registerSqlCommitReceipt } from "./sql-commit";
import type { AnyTableModel } from "./table-model";

export const SessionPendingKind = Schema.Literals(["Login", "StepUp"]);
export type SessionPendingKind = typeof SessionPendingKind.Type;

export const StoredSessionPending = Schema.Struct({
  kind: SessionPendingKind,
  digest: TokenDigest,
  version: SecurityRevision,
  flowId: AuthenticationFlowId,
  subjectId: SubjectId,
  bindingDigest: TokenDigest,
  snapshot: Schema.String,
  expiresAtMillis: Schema.Int,
  attemptLimit: Schema.Int.check(Schema.isGreaterThan(0)),
  failedAttempts: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
});

export type StoredSessionPending = typeof StoredSessionPending.Type;

type Mapping = SessionPendingTables<AnyTableModel, unknown> &
  Pick<SessionExecution, "moduleId" | "clock"> & { readonly subjectId: SubjectIdCodec<unknown> };

/** All consumers bind the module and kind through this owner. A caller never
 * supplies an optional discriminator and payload is decoded only after it matches. */
export const makeNativeSessionPending = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: Mapping,
  batch = false,
) {
  const sql = (yield* SqlClient).withoutTransforms();

  const p = mapping.pending,
    table = tables(p.table),
    now = tables.expression(mapping.clock.engineNowMillis);

  const exact = (t: SqlTable, key: string, value: unknown) =>
    exactSqlText(sql, t.column(key), t.value(key, value));

  const millis = (t: SqlTable, key: string) =>
    tables.expression(mapping.clock.toMillis(t.column(key)));

  const scope = (t: SqlTable, kind: SessionPendingKind) =>
    sql.and([exact(t, p.moduleId, mapping.moduleId), exact(t, p.kind, kind)]);

  const live = (t: SqlTable) =>
    sql.and([
      sql`${t.column(p.consumed)} = ${t.value(p.consumed, false)}`,
      sql`${millis(t, p.expiresAt)} > ${now}`,
      sql`${t.column(p.failedAttempts)} >= 0`,
      sql`${t.column(p.failedAttempts)} < ${t.column(p.attemptLimit)}`,
    ]);

  const predicate = (t: SqlTable, kind: SessionPendingKind, digest: TokenDigest) =>
    sql.and([scope(t, kind), exact(t, p.digest, digest), live(t)]);

  const decode = Effect.fnUntraced(function* (
    kind: SessionPendingKind,
    row: Record<string, unknown>,
  ) {
    sessionInvariant(
      row[p.moduleId] === mapping.moduleId &&
        row[p.kind] === kind &&
        (row[p.consumed] === false || row[p.consumed] === 0),
    );

    return yield* Schema.decodeUnknownEffect(StoredSessionPending)({
      kind,
      digest: row[p.digest],
      version: row[p.version],
      flowId: row[p.flowId],
      subjectId: yield* mapping.subjectId.toSubject(row[p.subjectId]),
      bindingDigest: row[p.bindingDigest],
      snapshot: row[p.snapshot],
      expiresAtMillis: mapping.clock.decodeInstant(row[p.expiresAt]),
      attemptLimit: row[p.attemptLimit],
      failedAttempts: row[p.failedAttempts],
    });
  });

  const read = Effect.fnUntraced(function* (kind: SessionPendingKind, digest: TokenDigest) {
    const rows =
      yield* sql`select ${table.fields("pending_")}, ${now} as engine_now from ${table.name} where ${predicate(table, kind, digest)} limit 2`;

    sessionInvariant(rows.length <= 1);
    if (rows[0] === undefined) return undefined;

    return {
      record: yield* decode(kind, table.decode(rows[0], "pending_")),
      now: Number(rows[0].engine_now),
    };
  });

  const stage = Effect.fnUntraced(function* (statement: Fragment, expected?: number) {
    if (batch) {
      yield* appendSqlBatchStatement(sql`${statement}`);
      if (expected !== undefined)
        yield* appendSqlBatchStatement(sqlBatchAssertion(sql, sql`changes() = ${expected}`));

      return expected;
    }
    const changed = yield* executeSqlChange(sql, statement);

    if (expected !== undefined) sessionInvariant(changed === expected);

    return changed;
  });

  const insert = Effect.fnUntraced(function* (
    input: SessionPendingInsert<unknown>,
    condition: Fragment = sql`1 = 1`,
  ) {
    sessionInvariant(input.moduleId === mapping.moduleId);

    const row = {
      ...p.encodeInsert(input),
      [p.moduleId]: mapping.moduleId,
      [p.kind]: input.kind,
      [p.digest]: input.digest,
      [p.version]: input.version,
      [p.flowId]: input.flowId,
      [p.subjectId]: input.subjectId,
      [p.bindingDigest]: input.bindingDigest,
      [p.snapshot]: input.snapshot,
      [p.expiresAt]: p.encodeInstant(input.expiresAt),
      [p.attemptLimit]: input.attemptLimit,
      [p.failedAttempts]: 0,
      [p.consumed]: false,
    };

    yield* stage(conditionalSqlInsert(sql, table, row, condition), 1);
  });

  const consumption = (kind: SessionPendingKind, input: PendingConsumption, native: unknown) =>
    sql.and([
      predicate(table, kind, input.digest),
      exact(table, p.version, input.version),
      exact(table, p.flowId, input.flowId),
      exact(table, p.bindingDigest, input.bindingDigest),
      sql`${table.column(p.subjectId)} = ${table.value(p.subjectId, native)}`,
    ]);

  const consume = (
    kind: SessionPendingKind,
    input: PendingConsumption,
    native: unknown,
    condition: Fragment = sql`1 = 1`,
  ) =>
    stage(
      sql`${table.update({ [p.consumed]: true })} where ${consumption(kind, input, native)} and ${condition}`,
      1,
    );

  const reject = (kind: SessionPendingKind, digest: TokenDigest) =>
    stage(
      sql`${table.update({ [p.failedAttempts]: sql`${table.column(p.failedAttempts)} + 1` })} where ${predicate(table, kind, digest)}`,
    );

  const clockCondition = (record: StoredSessionPending) => sql`${now} < ${record.expiresAtMillis}`;

  const consumedCondition = (
    kind: SessionPendingKind,
    input: PendingConsumption,
    native: unknown,
  ) =>
    sql`exists(select 1 from ${table.name} where ${scope(table, kind)} and ${exact(table, p.digest, input.digest)} and ${exact(table, p.version, input.version)} and ${exact(table, p.flowId, input.flowId)} and ${exact(table, p.bindingDigest, input.bindingDigest)} and ${table.column(p.subjectId)} = ${table.value(p.subjectId, native)} and ${table.column(p.consumed)} = ${table.value(p.consumed, true)})`;

  return {
    table,
    p,
    now,
    scope,
    live,
    predicate,
    decode,
    read,
    insert,
    consumption,
    consume,
    reject,
    stage,
    clockCondition,
    consumedCondition,
  };
});

export const prepareNativeSession = <Value, A>(
  value: Value,
  project: (value: Value, journal: CommitJournal) => PreparedCommit<A>,
) =>
  Effect.gen(function* () {
    const owner = yield* CurrentSqlCommit;

    if (owner.mode === "batch" && owner.statements.length === 0) {
      const sql = yield* SqlClient;

      yield* appendSqlBatchStatement(sql`select 1`);
    }
    const receipt = project(value, yield* CurrentCommitJournal);

    yield* registerSqlCommitReceipt(receipt);

    return receipt;
  });
