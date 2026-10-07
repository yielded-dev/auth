import { reportAuthFailure } from "@yielded/auth/Persistence";
import type { SubjectId } from "@yielded/auth/Schema";
import {
  type AuthenticationRequirement,
  AuthenticationRevision,
  SessionConflict,
  SessionInvalid,
  SessionUnavailable,
  SessionStepUpInvalid,
  PendingAuthenticationInvalid,
  StaleAuthentication,
  assessAuthentication,
  type AuthenticationEvidence,
} from "@yielded/auth/Sessions";
import { Cause, Effect, Schema, DateTime } from "effect";
import { SqlClient } from "effect/sql/SqlClient";
import type { Fragment } from "effect/sql/Statement";

import { PersistenceMappingError } from "./mapping-error";
import type { SessionAuthorityTables, SessionExecution } from "./models/session-model";
import type { NativeSqlTables, SqlTable } from "./native-sql-table";
import { anySqlCondition, exactSqlText } from "./sql-change";
import type { AnyTableModel } from "./table-model";

export const sessionUnavailable = () => SessionUnavailable.make({});

export const sessionInvariant: (condition: unknown) => asserts condition = (condition) => {
  if (!condition)
    throw PersistenceMappingError.make({ operation: "decode", cause: "Invalid session authority" });
};

export type SessionDomainFailure =
  | SessionConflict
  | SessionInvalid
  | SessionUnavailable
  | SessionStepUpInvalid
  | PendingAuthenticationInvalid
  | StaleAuthentication;

const isDomainFailure = (error: unknown): error is SessionDomainFailure =>
  Schema.is(SessionConflict)(error) ||
  Schema.is(SessionInvalid)(error) ||
  Schema.is(SessionUnavailable)(error) ||
  Schema.is(SessionStepUpInvalid)(error) ||
  Schema.is(PendingAuthenticationInvalid)(error) ||
  Schema.is(StaleAuthentication)(error);

/** Only schema-checked domain failures cross the owner boundary; SQL/mapping
 * failures remain Unavailable. The executor preserves every mixed cause reason. */
export const sessionFailure = <E>(
  error: E,
): Extract<E, SessionDomainFailure> | SessionUnavailable =>
  isDomainFailure(error) ? (error as Extract<E, SessionDomainFailure>) : sessionUnavailable();

export const normalizeSessionOperation = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(
    Effect.tapError((error) =>
      isDomainFailure(error)
        ? Effect.void
        : reportAuthFailure("auth-persistence", Cause.fail(error)),
    ),
    Effect.mapError(sessionFailure),
  );

export type NativeSessionAuthorityMapping = SessionAuthorityTables<
  AnyTableModel,
  AnyTableModel,
  unknown
> &
  SessionExecution;

export interface NativeSessionAuthority {
  readonly native: unknown;
  readonly row: Record<string, unknown>;
  readonly revision: AuthenticationRevision;
  readonly requirement: AuthenticationRequirement;
  readonly now: number;
}

export const sameSessionRevision = (left: AuthenticationRevision, right: AuthenticationRevision) =>
  left.subjectId === right.subjectId &&
  left.securityRevision === right.securityRevision &&
  left.credentials.length === right.credentials.length &&
  new Set(left.credentials.map((f) => f.credentialId)).size === left.credentials.length &&
  left.credentials.every((f) =>
    right.credentials.some(
      (other) => other.credentialId === f.credentialId && other.revision === f.revision,
    ),
  );

/** Known-subject joins bind each physical ID column independently. Subject locks
 * precede every credential lock, including inside an application coordinator. */
export const makeNativeSessionAuthorityState = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: NativeSessionAuthorityMapping,
  batch = false,
) {
  const sql = (yield* SqlClient).withoutTransforms();

  const s = mapping.subject,
    c = mapping.credential;

  if (batch) sessionInvariant(s.requirementColumns !== undefined);

  const subject = tables(s.table),
    credential = tables(c.table);

  const joinedSubject = subject.as("session_subject"),
    joinedCredential = credential.as("session_factor");

  const now = tables.expression(mapping.clock.engineNowMillis);
  const lock = sql.onDialectOrElse({ sqlite: () => sql``, orElse: () => sql`for update` });
  const nativeLocks = !batch && sql.onDialectOrElse({ sqlite: () => false, orElse: () => true });

  const exact = (table: SqlTable, key: string, value: unknown) =>
    exactSqlText(sql, table.column(key), table.value(key, value));

  const id = (table: SqlTable, key: string, value: unknown) =>
    sql`${table.column(key)} = ${table.value(key, value)}`;

  const activeSubject = (table: SqlTable) => id(table, s.status, s.activeStatusValue);

  const activeCredential = (table: SqlTable) => {
    if (c.status === undefined) return sql`1 = 1`;
    sessionInvariant(c.activeStatusValue !== undefined);

    return id(table, c.status, c.activeStatusValue);
  };

  const requested = (table: SqlTable, ids: ReadonlyArray<string>) =>
    anySqlCondition(
      sql,
      ids.map((value) => exact(table, c.credentialId, value)),
    );

  const decode = Effect.fnUntraced(function* (
    subjectId: SubjectId,
    native: unknown,
    row: Record<string, unknown>,
    factors: ReadonlyArray<Record<string, unknown>>,
    instant: unknown,
  ): Effect.fn.Return<
    NativeSessionAuthority | undefined,
    PersistenceMappingError | Schema.SchemaError
  > {
    sessionInvariant((yield* mapping.subjectId.toSubject(row[s.id])) === subjectId);
    if (!s.isActiveStatus(row[s.status])) return undefined;
    const credentials: { credentialId: string; revision: string }[] = [];

    for (const factor of factors) {
      if (factor[c.credentialId] === null || factor[c.credentialId] === undefined) continue;
      sessionInvariant((yield* mapping.subjectId.toSubject(factor[c.subjectId])) === subjectId);
      if (c.status !== undefined) sessionInvariant(c.isActiveStatus?.(factor[c.status]) === true);

      const value = yield* Schema.decodeUnknownEffect(
        Schema.Struct({ credentialId: Schema.String, revision: Schema.String }),
      )({ credentialId: factor[c.credentialId], revision: factor[c.revision] });

      sessionInvariant(!credentials.some((other) => other.credentialId === value.credentialId));
      credentials.push(value);
    }
    sessionInvariant(credentials.length <= 64);

    return {
      native,
      row,
      revision: yield* Schema.decodeUnknownEffect(AuthenticationRevision)({
        subjectId,
        securityRevision: row[s.securityRevision],
        credentials: credentials.sort((a, b) => a.credentialId.localeCompare(b.credentialId)),
      }),
      requirement: yield* s.decodeRequirement(row),
      now: yield* Schema.decodeEffect(Schema.Int)(Number(instant)),
    };
  });

  const read = Effect.fnUntraced(function* (subjectId: SubjectId, locking = false) {
    const native = yield* mapping.subjectId.toNative(subjectId);

    sessionInvariant((yield* mapping.subjectId.toSubject(native)) === subjectId);
    if (locking && nativeLocks) {
      const owners =
        yield* sql`select ${subject.fields("s_")}, ${now} as engine_now from ${subject.name} where ${id(subject, s.id, native)} and ${activeSubject(subject)} limit 2 ${lock}`;

      sessionInvariant(owners.length <= 1);
      if (owners[0] === undefined) return undefined;

      const factors =
        yield* sql`select ${credential.fields("c_")} from ${credential.name} where ${id(credential, c.subjectId, native)} and ${activeCredential(credential)} order by ${credential.column(c.credentialId)} limit 65 ${lock}`;

      return yield* decode(
        subjectId,
        native,
        subject.decode(owners[0], "s_"),
        factors.map((row) => credential.decode(row, "c_")),
        owners[0].engine_now,
      );
    }

    const rows =
      yield* sql`select ${joinedSubject.fields("s_")}, ${joinedCredential.fields("c_")}, ${now} as engine_now from ${joinedSubject.name} left join ${joinedCredential.name} on ${id(joinedCredential, c.subjectId, native)} and ${activeCredential(joinedCredential)} where ${id(joinedSubject, s.id, native)} and ${activeSubject(joinedSubject)} limit 65`;

    if (rows[0] === undefined) return undefined;

    return yield* decode(
      subjectId,
      native,
      joinedSubject.decode(rows[0], "s_"),
      rows.map((row) => joinedCredential.decode(row, "c_")),
      rows[0].engine_now,
    );
  });

  const policyCondition = (row: Record<string, unknown>, native: unknown): Fragment => {
    if (!batch) return sql`1 = 1`;
    sessionInvariant(s.requirementColumns !== undefined);

    return sql`exists(select 1 from ${subject.name} where ${id(subject, s.id, native)} and ${sql.and(s.requirementColumns.map((key) => (row[key] === null ? sql`${subject.column(key)} is null` : typeof row[key] === "string" ? exact(subject, key, row[key]) : id(subject, key, row[key]))))})`;
  };

  const authorityCondition = (revision: AuthenticationRevision, native: unknown): Fragment =>
    sql.and([
      sql`exists(select 1 from ${subject.name} where ${id(subject, s.id, native)} and ${exact(subject, s.securityRevision, revision.securityRevision)} and ${activeSubject(subject)})`,
      sql`(select count(*) from ${credential.name} where ${id(credential, c.subjectId, native)} and ${activeCredential(credential)}) = ${revision.credentials.length}`,
      ...revision.credentials.map(
        (factor) =>
          sql`exists(select 1 from ${credential.name} where ${id(credential, c.subjectId, native)} and ${exact(credential, c.credentialId, factor.credentialId)} and ${exact(credential, c.revision, factor.revision)} and ${activeCredential(credential)})`,
      ),
    ]);

  return {
    sql,
    subject,
    credential,
    joinedSubject,
    joinedCredential,
    now,
    lock,
    nativeLocks,
    exact,
    id,
    activeSubject,
    activeCredential,
    requested,
    decode,
    read,
    authorityCondition,
    policyCondition,
  };
});

/** Evaluate freshness at the database sample. The final write also enforces the
 * earliest future boundary at which the same evidence would cease to satisfy. */
export const assessSessionAt = Effect.fnUntraced(function* (
  evidence: AuthenticationEvidence,
  requirement: AuthenticationRequirement,
  now: number,
) {
  const result = yield* assessAuthentication(evidence, requirement, DateTime.makeUnsafe(now));

  return result;
});
