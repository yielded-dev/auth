import { TokenDigest, type SubjectId } from "@yielded/auth/Schema";
import { SecurityRevision, SessionId } from "@yielded/auth/Sessions";
import { Context, Effect, Option, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";

import type { StatefulSessionMapping } from "./models/session-model";
import type {
  SessionTransactionOwner,
  SessionFlowRead,
  SessionSubjectAuthority,
  SessionVerificationReader,
  StatefulSessionStore,
} from "./session-store";
import {
  decodeSqlRow,
  sqlAlias,
  sqlName,
  requireSqlTable,
  sqlColumn,
  sqlProjection,
  sqlTable,
  sqlValue,
  sqlInsert,
  sqlUpdate,
} from "./sql-metadata";

class CurrentSqlSessionOwner extends Context.Service<CurrentSqlSessionOwner, object>()(
  "@yielded/auth-persistence/CurrentSqlSessionOwner",
) {}

/* oxlint-disable no-explicit-any -- a validated mapping carries backend table metadata. */
export const makeSqlSessionVerification = <Claims>(
  client: SqlClient,
  mapping: StatefulSessionMapping<Claims, any, any, any, any, any, any, any>,
): SessionVerificationReader<Claims> => {
  const sql = client.withoutTransforms();
  const sessions = requireSqlTable(mapping.session.table);
  const subjects = requireSqlTable(mapping.subject.table);
  const digest = sqlColumn(sql, sessions, mapping.session.digest, "s");
  const sessionOwner = sqlColumn(sql, sessions, mapping.session.subjectId, "s");
  const subjectId = sqlColumn(sql, subjects, mapping.subject.id, "a");

  const authority = (row: Readonly<Record<string, unknown>>) =>
    Schema.decodeUnknownEffect(SecurityRevision)(row[mapping.subject.securityRevision]).pipe(
      Effect.map((securityRevision) => ({
        active: mapping.subject.isActiveStatus(row[mapping.subject.status]),
        securityRevision,
      })),
    );

  const pointRead = (value: TokenDigest) =>
    sql.withTransaction(
      Effect.gen(function* () {
        const rows =
          yield* sql`select ${sqlProjection(sql, sessions, "s")} from ${sqlTable(sql, sessions)} as s where ${digest} = ${value} limit 1`;

        if (rows[0] === undefined) return undefined;
        const record = yield* mapping.session.decode(yield* decodeSqlRow(sessions, rows[0]));
        const native = yield* mapping.subjectId.toNative(record.subjectId);

        const owners =
          yield* sql`select ${sqlProjection(sql, subjects, "a")} from ${sqlTable(sql, subjects)} as a where ${subjectId} = ${sqlValue(sql, subjects, mapping.subject.id, native)} limit 1`;

        return {
          record,
          authority:
            owners[0] === undefined
              ? undefined
              : yield* authority(yield* decodeSqlRow(subjects, owners[0])),
        };
      }),
    );

  return {
    readForVerification: (value) =>
      Effect.gen(function* () {
        if (
          sessions.columns[mapping.session.subjectId]!.options.type !==
          subjects.columns[mapping.subject.id]!.options.type
        )
          return yield* pointRead(value);

        const rows =
          yield* sql`select ${sqlProjection(sql, sessions, "s", "session_")}, ${sqlProjection(sql, subjects, "a", "subject_")}, cast(${sessionOwner} as text) as owner_key, cast(${subjectId} as text) as authority_key from ${sqlTable(sql, sessions)} as s left join ${sqlTable(sql, subjects)} as a on ${subjectId} = ${sessionOwner} where ${digest} = ${value} limit 1`;

        const row = rows[0];

        if (row === undefined) return undefined;
        const stored = yield* decodeSqlRow(sessions, row, "session_");
        const record = yield* mapping.session.decode(stored);
        const native = yield* mapping.subjectId.toNative(record.subjectId);
        const expected = sqlValue(sql, subjects, mapping.subject.id, native);

        const sessionBinding = sqlValue(
          sql,
          sessions,
          mapping.session.subjectId,
          stored[mapping.session.subjectId],
        );

        const scalar =
          typeof expected === "string" ||
          typeof expected === "boolean" ||
          typeof expected === "bigint" ||
          (typeof expected === "number" && Number.isFinite(expected));

        if (
          !scalar ||
          !Object.is(expected, sessionBinding) ||
          row.owner_key !== String(expected) ||
          (row.authority_key !== null && row.authority_key !== String(expected))
        )
          return yield* pointRead(value);

        return {
          record,
          authority:
            row.authority_key === null
              ? undefined
              : yield* authority(yield* decodeSqlRow(subjects, row, "subject_")),
        };
      }),
  };
};

export const makeSqlStatefulSessionOwner = <Claims>(
  client: SqlClient,
  mapping: StatefulSessionMapping<Claims, any, any, any, any, any, any, any>,
): SessionTransactionOwner<StatefulSessionStore<Claims>> => {
  const sql = client.withoutTransforms();
  const subjects = requireSqlTable(mapping.subject.table);
  const credentials = requireSqlTable(mapping.credential.table);
  const sessions = requireSqlTable(mapping.session.table);
  const flows = requireSqlTable(mapping.flow.table);

  const aliases = {
    session_authority: sqlName(
      sql,
      sqlAlias([sessions, subjects, credentials, flows], "session_authority"),
    ),
    session_credentials: sqlName(
      sql,
      sqlAlias([sessions, subjects, credentials, flows], "session_credentials"),
    ),
    session_flow: sqlName(sql, sqlAlias([sessions, subjects, credentials, flows], "session_flow")),
  };

  const subjectId = sqlColumn(sql, subjects, mapping.subject.id);
  const sessionId = sqlColumn(sql, sessions, mapping.session.sessionId);
  const digest = sqlColumn(sql, sessions, mapping.session.digest);
  const sessionSubject = sqlColumn(sql, sessions, mapping.session.subjectId);

  const lock = (locking: boolean) =>
    locking ? sql.onDialectOrElse({ pg: () => sql`for update`, orElse: () => sql`` }) : sql``;

  const subjectAuthority = (row: Readonly<Record<string, unknown>>) =>
    Schema.decodeUnknownEffect(SecurityRevision)(row[mapping.subject.securityRevision]).pipe(
      Effect.map((securityRevision): SessionSubjectAuthority => ({
        active: mapping.subject.isActiveStatus(row[mapping.subject.status]),
        securityRevision,
        requirement: mapping.subject.decodeRequirement(row),
      })),
    );

  const flowRead = Effect.fnUntraced(function* (row: Readonly<Record<string, unknown>>) {
    return {
      pending: row[mapping.flow.state] === mapping.flow.pendingStateValue,
      pendingDigest:
        row[mapping.flow.pendingDigest] === null
          ? undefined
          : yield* Schema.decodeUnknownEffect(TokenDigest)(row[mapping.flow.pendingDigest]),
      dedupUntil: yield* mapping.flow.decodeInstant(row[mapping.flow.dedupUntil]),
    } satisfies SessionFlowRead;
  });

  const credentialRead = (row: Readonly<Record<string, unknown>>) =>
    Schema.decodeUnknownEffect(SecurityRevision)(row[mapping.credential.revision]).pipe(
      Effect.map((revision) => ({
        credentialId: String(row[mapping.credential.credentialId]),
        revision,
        active:
          mapping.credential.status === undefined ||
          mapping.credential.isActiveStatus?.(row[mapping.credential.status]) === true,
      })),
    );

  const decodeSession = (rows: ReadonlyArray<Readonly<Record<string, unknown>>>) =>
    rows[0] === undefined
      ? Effect.succeed(undefined)
      : decodeSqlRow(sessions, rows[0]).pipe(Effect.flatMap(mapping.session.decode));

  const readSubject = Effect.fnUntraced(function* (id: SubjectId, locking: boolean) {
    const native = yield* mapping.subjectId.toNative(id);

    const rows =
      yield* sql`select ${sqlProjection(sql, subjects)} from ${sqlTable(sql, subjects)} where ${subjectId} = ${sqlValue(sql, subjects, mapping.subject.id, native)} limit 1 ${lock(locking)}`;

    return rows[0] === undefined
      ? undefined
      : yield* subjectAuthority(yield* decodeSqlRow(subjects, rows[0]));
  });

  const store: StatefulSessionStore<Claims> = {
    ...makeSqlSessionVerification(sql, mapping),
    readSubject,
    readAuthority: (id, requested, locking, flowId) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(id);
        const nativeSubject = sqlValue(sql, subjects, mapping.subject.id, native);
        const credentialOwner = sqlColumn(sql, credentials, mapping.credential.subjectId);
        const credentialId = sqlColumn(sql, credentials, mapping.credential.credentialId);
        const flowKey = sqlColumn(sql, flows, mapping.flow.flowId);
        const materialized = locking ? sql`materialized` : sql``;

        // CTE dependencies preserve subject -> credential -> flow lock order.
        // Each mapped key binds independently; column representation need not
        // support a physical join with the application's subject table.
        const rows = yield* sql`
          with ${aliases.session_authority} as ${materialized} (
            select * from ${sqlTable(sql, subjects)}
            where ${subjectId} = ${nativeSubject} limit 1 ${lock(locking)}
          ), ${aliases.session_credentials} as ${materialized} (
            select * from ${sqlTable(sql, credentials)}
            where ${credentialOwner} = ${sqlValue(sql, credentials, mapping.credential.subjectId, native)}
              and ${requested.length === 0 ? sql`false` : sql`${credentialId} in ${sql.in(requested)}`}
              and (select count(*) from ${aliases.session_authority}) >= 0
            order by ${credentialId} ${lock(locking)}
          ), ${aliases.session_flow} as ${materialized} (
            select * from ${sqlTable(sql, flows)}
            where ${flowId === undefined ? sql`false` : sql`${flowKey} = ${flowId}`}
              and (select count(*) from ${aliases.session_credentials}) >= 0
            limit 1 ${lock(locking)}
          )
          select ${sqlProjection(sql, subjects, "a", "subject_")},
            ${sqlProjection(sql, credentials, "c", "credential_")},
            ${sqlProjection(sql, flows, "f", "flow_")}
          from ${aliases.session_authority} as a
          left join ${aliases.session_credentials} as c on true
          left join ${aliases.session_flow} as f on true
          order by ${sqlColumn(sql, credentials, mapping.credential.credentialId, "c")}
        `;

        const row = rows[0];

        if (row === undefined) return { subject: undefined, credentials: [], flow: undefined };

        return {
          subject: yield* subjectAuthority(yield* decodeSqlRow(subjects, row, "subject_")),
          credentials: yield* Effect.forEach(
            rows.filter((row) => row["credential_" + mapping.credential.credentialId] !== null),
            (row) =>
              decodeSqlRow(credentials, row, "credential_").pipe(Effect.flatMap(credentialRead)),
          ),
          flow:
            row["flow_" + mapping.flow.flowId] === null
              ? undefined
              : yield* flowRead(yield* decodeSqlRow(flows, row, "flow_")),
        };
      }),
    lockRotation: (id) =>
      Effect.gen(function* () {
        const native = yield* mapping.sessionId.toNative(id);

        const initial = yield* decodeSession(
          yield* sql`select ${sqlProjection(sql, sessions)} from ${sqlTable(sql, sessions)} where ${sessionId} = ${native} limit 1`,
        );

        if (initial === undefined) return undefined;
        const authority = yield* readSubject(initial.subjectId, true);

        const record = yield* decodeSession(
          yield* sql`select ${sqlProjection(sql, sessions)} from ${sqlTable(sql, sessions)} where ${sessionId} = ${native} limit 1 ${lock(true)}`,
        );

        return record === undefined ? undefined : { record, authority };
      }),
    lockDigest: (value) =>
      Effect.gen(function* () {
        const initial = yield* decodeSession(
          yield* sql`select ${sqlProjection(sql, sessions)} from ${sqlTable(sql, sessions)} where ${digest} = ${value} limit 1`,
        );

        if (initial === undefined) return false;
        yield* readSubject(initial.subjectId, true);

        const rows =
          yield* sql`select 1 as present from ${sqlTable(sql, sessions)} where ${digest} = ${value} limit 1 ${lock(true)}`;

        return rows.length > 0;
      }),
    establish: (record, evidence, _pending, replaceFlow, nativeSession) =>
      Effect.gen(function* () {
        const nativeSubject = yield* mapping.subjectId.toNative(record.subjectId);

        if (replaceFlow)
          yield* sql`delete from ${sqlTable(sql, flows)} where ${sqlColumn(sql, flows, mapping.flow.flowId)} = ${evidence.flowId}`;
        yield* sql`insert into ${sqlTable(sql, flows)} ${sqlInsert(sql, flows, mapping.flow.encodeEstablishedInsert({ evidence, subjectId: nativeSubject, dedupUntil: record.absoluteExpiresAt }))}`;
        yield* sql`insert into ${sqlTable(sql, sessions)} ${sqlInsert(sql, sessions, mapping.session.encodeInsert(record, { subjectId: nativeSubject, sessionId: nativeSession }))}`;
      }),
    rotate: (input, next) =>
      Effect.gen(function* () {
        const native = yield* mapping.sessionId.toNative(input.sessionId);

        yield* sql`update ${sqlTable(sql, sessions)} set ${sqlUpdate(sql, sessions, mapping.session.encodeRotation(next))} where ${sessionId} = ${native} and ${digest} = ${input.expectedDigest} and ${sqlColumn(sql, sessions, mapping.session.version)} = ${input.expectedVersion}`;
      }),
    revokeDigest: (value) =>
      sql`delete from ${sqlTable(sql, sessions)} where ${digest} = ${value}`.pipe(Effect.asVoid),
    revoke: (input) =>
      Effect.gen(function* () {
        const nativeSubject = yield* mapping.subjectId.toNative(input.subjectId);
        const nativeSession = yield* mapping.sessionId.toNative(input.sessionId);

        yield* sql`delete from ${sqlTable(sql, sessions)} where ${sessionSubject} = ${sqlValue(sql, sessions, mapping.session.subjectId, nativeSubject)} and ${sessionId} = ${nativeSession}`;
      }),
    revokeAll: (input, next) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(input.subjectId);

        yield* sql`update ${sqlTable(sql, subjects)} set ${sqlUpdate(sql, subjects, { [mapping.subject.securityRevision]: next })} where ${subjectId} = ${sqlValue(sql, subjects, mapping.subject.id, native)} and ${sqlColumn(sql, subjects, mapping.subject.securityRevision)} = ${input.expectedSecurityRevision}`;
        yield* sql`delete from ${sqlTable(sql, sessions)} where ${sessionSubject} = ${sqlValue(sql, sessions, mapping.session.subjectId, native)}`;
      }),
    readPage: (input) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(input.subjectId);

        const cursor =
          input.cursor === undefined
            ? undefined
            : yield* mapping.sessionId.toNative(
                yield* Schema.decodeEffect(SessionId)(input.cursor),
              );

        const now = mapping.session.encodeInstant(input.now);

        const rows =
          yield* sql`select ${sqlProjection(sql, sessions)} from ${sqlTable(sql, sessions)} where ${sessionSubject} = ${sqlValue(sql, sessions, mapping.session.subjectId, native)} and ${sqlColumn(sql, sessions, mapping.session.securityRevision)} = ${input.securityRevision} and ${sqlColumn(sql, sessions, mapping.session.expiresAt)} > ${now} and ${sqlColumn(sql, sessions, mapping.session.absoluteExpiresAt)} > ${now} ${cursor === undefined ? sql`` : sql`and ${sessionId} > ${cursor}`} order by ${sessionId} limit ${input.limit}`;

        return yield* Effect.forEach(rows, (row) =>
          decodeSqlRow(sessions, row).pipe(Effect.flatMap(mapping.session.decode)),
        );
      }),
  };

  const owner = {};

  return {
    read: store,
    isCurrent: Effect.serviceOption(CurrentSqlSessionOwner).pipe(
      Effect.map((current) => Option.isSome(current) && current.value === owner),
    ),
    transaction: (body) =>
      sql.withTransaction(body(store)).pipe(Effect.provideService(CurrentSqlSessionOwner, owner)),
  };
};
