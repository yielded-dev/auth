import {
  type SessionAuthorityReader,
  type SessionAuthorityStore,
  type SessionPendingStore,
  type PendingAuthenticationTables,
  type AuthenticationAuthorityMapping,
  type SessionAuthorityTables,
  type SessionFlowTables,
  type SessionTransactionOwner,
  type StatefulSessionMapping,
  type StatefulSessionStore,
} from "@yielded/auth-persistence/Adapter";
import { TokenDigest } from "@yielded/auth/Schema";
import { SecurityRevision, SessionId } from "@yielded/auth/Sessions";
import { and, eq, gt } from "drizzle-orm";
import { Effect, Option, Schema } from "effect";

import { column, updateValues } from "./model";
import { NativeDatabase } from "./native-database";
import type { NativeSqlDatabase } from "./native-database";
import { CurrentSessionSql } from "./session-database";
import { makeSessionVerificationReader } from "./session-verification";
import { readSnapshot } from "./sql-snapshot";

/* oxlint-disable no-explicit-any -- native mappings erase foreign table shapes; persisted values use mapped decoders. */
type AuthorityMapping = SessionAuthorityTables<any, any, any> &
  Partial<SessionFlowTables<any, any>>;
type Database = NativeSqlDatabase;
type Dialect = "pg" | "sqlite" | undefined;

const selectRows = (query: ReturnType<Database["select"]>, locking: boolean) =>
  locking && typeof query.for === "function" ? query.for("update") : query;

const decodeSubject = (mapping: AuthorityMapping, row: Record<string, unknown> | undefined) =>
  row === undefined
    ? Effect.succeed(undefined)
    : Effect.map(
        Schema.decodeUnknownEffect(SecurityRevision)(row[mapping.subject.securityRevision]),
        (securityRevision) => ({
          active: mapping.subject.isActiveStatus(row[mapping.subject.status]),
          securityRevision,
          requirement: mapping.subject.decodeRequirement(row),
        }),
      );

const decodeFlow = (
  mapping: Partial<SessionFlowTables<any, any>>,
  row: Record<string, unknown> | undefined,
) =>
  Effect.gen(function* () {
    if (row === undefined || mapping.flow === undefined) return undefined;
    const digest = row[mapping.flow.pendingDigest];

    return {
      pending: row[mapping.flow.state] === mapping.flow.pendingStateValue,
      pendingDigest:
        digest === null || digest === undefined
          ? undefined
          : yield* Schema.decodeUnknownEffect(TokenDigest)(digest),
      dedupUntil: yield* mapping.flow.decodeInstant(row[mapping.flow.dedupUntil]),
    };
  });

const subjectReader =
  (mapping: AuthorityMapping, database: Database) =>
  (subjectId: Parameters<StatefulSessionStore<unknown>["readSubject"]>[0], locking: boolean) =>
    Effect.gen(function* () {
      const nativeSubjectId = yield* mapping.subjectId.toNative(subjectId);

      const rows = yield* selectRows(
        database
          .select()
          .from(mapping.subject.table)
          .where(eq(column(mapping.subject.table, mapping.subject.id), nativeSubjectId))
          .limit(1),
        locking,
      );

      return yield* decodeSubject(mapping, rows[0]);
    });

/** Native snapshot and lock ordering belong to this backend; the caller decides
 * whether the decoded authority and revision authorize the operation. */
export const sessionAuthorityReader = (
  mapping: AuthorityMapping,
  database: Database,
  dialect: Dialect,
): SessionAuthorityReader => ({
  readAuthority: (subjectId, credentialIds, locking, flowId) =>
    Effect.gen(function* () {
      const nativeSubjectId = yield* mapping.subjectId.toNative(subjectId);
      const credentialId = column(mapping.credential.table, mapping.credential.credentialId);

      const reads = [
        {
          table: mapping.subject.table,
          where: eq(column(mapping.subject.table, mapping.subject.id), nativeSubjectId),
          limit: 1,
        },
        {
          table: mapping.credential.table,
          where: eq(
            column(mapping.credential.table, mapping.credential.subjectId),
            nativeSubjectId,
          ),
          orderBy: [credentialId],
          limit: 4097,
        },
        ...(flowId === undefined || mapping.flow === undefined
          ? []
          : [
              {
                table: mapping.flow.table,
                where: eq(column(mapping.flow.table, mapping.flow.flowId), flowId),
                limit: 1,
              },
            ]),
      ];

      let rows: ReadonlyArray<ReadonlyArray<Record<string, any>>>;

      if (!locking || dialect !== undefined) {
        const snapshot = readSnapshot(
          database,
          reads,
          database.maxParameters,
          locking && dialect === "pg",
        );

        if (!locking && !snapshot.singleStatement)
          return yield* database.transaction((transaction) =>
            sessionAuthorityReader(mapping, transaction, dialect).readAuthority(
              subjectId,
              credentialIds,
              true,
              flowId,
            ),
          );
        rows = yield* snapshot.rows;
      } else {
        rows = yield* Effect.forEach(reads, (read) => {
          let query = database.select().from(read.table).where(read.where);

          if ("limit" in read) query = query.limit(read.limit);
          if ("orderBy" in read) query = query.orderBy(...read.orderBy);

          return selectRows(query, true);
        });
      }

      const credentials = yield* Effect.forEach(rows[1] ?? [], (row) =>
        Effect.gen(function* () {
          return {
            credentialId: yield* Schema.decodeUnknownEffect(Schema.String)(
              row[mapping.credential.credentialId],
            ),
            revision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
              row[mapping.credential.revision],
            ),
            active:
              mapping.credential.status === undefined ||
              mapping.credential.isActiveStatus?.(row[mapping.credential.status]) === true,
          };
        }),
      );

      return {
        subject: yield* decodeSubject(mapping, rows[0]?.[0]),
        credentials: credentials.sort((left, right) =>
          left.credentialId.localeCompare(right.credentialId),
        ),
        flow: flowId === undefined ? undefined : yield* decodeFlow(mapping, rows[2]?.[0]),
      };
    }),
});

const sessionPendingStore = <Claims>(
  mapping: PendingAuthenticationTables<Claims, any, any, any>,
  current: Database,
): SessionPendingStore<Claims> => ({
  lockPending: (digest) =>
    Effect.gen(function* () {
      const pending = mapping.pending;

      const row = (yield* selectRows(
        current
          .select()
          .from(pending.table)
          .where(eq(column(pending.table, pending.digest), digest))
          .limit(1),
        true,
      ))[0];

      if (row === undefined) return undefined;
      const record = yield* pending.decode(row);

      const flow = (yield* selectRows(
        current
          .select()
          .from(mapping.flow.table)
          .where(eq(column(mapping.flow.table, mapping.flow.flowId), record.evidence.flowId))
          .limit(1),
        true,
      ))[0];

      return {
        record,
        failedAttempts: Number(row[pending.failedAttempts]),
        consumed: row[pending.consumed] !== false,
        flow: yield* decodeFlow(mapping, flow),
      };
    }),
  consumePending: (input, dedupUntil) =>
    Effect.gen(function* () {
      yield* current
        .update(mapping.pending.table)
        .set(updateValues([[mapping.pending.consumed, true]]))
        .where(
          and(
            eq(column(mapping.pending.table, mapping.pending.digest), input.digest),
            eq(column(mapping.pending.table, mapping.pending.version), input.version),
            eq(column(mapping.pending.table, mapping.pending.consumed), false),
          ),
        );
      yield* current
        .update(mapping.flow.table)
        .set(
          updateValues([
            [mapping.flow.state, mapping.flow.establishedStateValue],
            [mapping.flow.pendingDigest, null],
            [mapping.flow.dedupUntil, mapping.flow.encodeInstant(dedupUntil)],
          ]),
        )
        .where(eq(column(mapping.flow.table, mapping.flow.flowId), input.flowId));
    }),
});

export const makeSessionAuthorityOwner = Effect.fnUntraced(function* <Claims>(
  mapping: AuthenticationAuthorityMapping<Claims, any, any, any, any, any>,
) {
  const database = yield* CurrentSessionSql;

  const dialect = (yield* NativeDatabase).$client.onDialectOrElse({
    pg: () => "pg" as const,
    sqlite: () => "sqlite" as const,
    orElse: () => undefined,
  });

  const store = (current: Database): SessionAuthorityStore<Claims> => ({
    ...sessionAuthorityReader(mapping, current, dialect),
    ...(mapping.pending === undefined
      ? {}
      : { pending: sessionPendingStore(mapping.pending, current) }),
  });

  const owner: SessionTransactionOwner<SessionAuthorityStore<Claims>> = {
    read: store(database),
    isCurrent: Effect.map(
      Effect.serviceOption(CurrentSessionSql),
      (current) => Option.isSome(current) && current.value === database,
    ),
    transaction: (body) =>
      database.transaction((current) =>
        body(store(current)).pipe(Effect.provideService(CurrentSessionSql, current)),
      ),
  };

  return owner;
});

export const makeStatefulSessionOwner = Effect.fnUntraced(function* <Claims>(
  mapping: StatefulSessionMapping<Claims, any, any, any, any, any, any, any>,
  nativeDatabase: object,
) {
  // The composed adapter acquired this native Drizzle database. Erasure ends at
  // its query-builder shape; column codecs and domain records remain native.
  const database = nativeDatabase as NativeSqlDatabase;
  const native = yield* NativeDatabase;

  const dialect = native.$client.onDialectOrElse({
    pg: () => "pg" as const,
    sqlite: () => "sqlite" as const,
    orElse: () => undefined,
  });

  const makeStore = (current: Database): Effect.Effect<StatefulSessionStore<Claims>> =>
    Effect.gen(function* () {
      const verification = yield* makeSessionVerificationReader<Claims>(mapping).pipe(
        Effect.provideService(CurrentSessionSql, current),
        Effect.provideService(NativeDatabase, native),
      );

      const readSubject = subjectReader(mapping, current);

      const sessionColumn = (name: keyof typeof mapping.session) =>
        column(mapping.session.table, mapping.session[name] as string);

      const store: StatefulSessionStore<Claims> = {
        ...verification,
        ...sessionAuthorityReader(mapping, current, dialect),
        readSubject,
        ...(mapping.pending === undefined
          ? {}
          : {
              pending: sessionPendingStore<Claims>(
                { pending: mapping.pending, flow: mapping.flow },
                current,
              ),
            }),
        lockRotation: (sessionId) =>
          Effect.gen(function* () {
            const nativeSessionId = yield* mapping.sessionId.toNative(sessionId);
            const where = eq(sessionColumn("sessionId"), nativeSessionId);

            const initial = (yield* current
              .select()
              .from(mapping.session.table)
              .where(where)
              .limit(1))[0];

            if (initial === undefined) return undefined;
            const original = yield* mapping.session.decode(initial);
            const authority = yield* readSubject(original.subjectId, true);

            const row = (yield* selectRows(
              current.select().from(mapping.session.table).where(where).limit(1),
              true,
            ))[0];

            return row === undefined
              ? undefined
              : { record: yield* mapping.session.decode(row), authority };
          }),
        lockDigest: (digest) =>
          Effect.gen(function* () {
            const where = eq(sessionColumn("digest"), digest);

            const initial = (yield* current
              .select()
              .from(mapping.session.table)
              .where(where)
              .limit(1))[0];

            if (initial === undefined) return false;
            const record = yield* mapping.session.decode(initial);

            yield* readSubject(record.subjectId, true);

            return (
              (yield* selectRows(
                current.select().from(mapping.session.table).where(where).limit(1),
                true,
              ))[0] !== undefined
            );
          }),
        establish: (record, evidence, pending, replaceFlow, nativeSessionId) =>
          Effect.gen(function* () {
            const subjectId = yield* mapping.subjectId.toNative(record.subjectId);

            if (pending === undefined) {
              if (replaceFlow) {
                if (mapping.pending !== undefined)
                  yield* current
                    .delete(mapping.pending.table)
                    .where(
                      eq(column(mapping.pending.table, mapping.pending.flowId), evidence.flowId),
                    );
                yield* current
                  .delete(mapping.flow.table)
                  .where(eq(column(mapping.flow.table, mapping.flow.flowId), evidence.flowId));
              }
              yield* current.insert(mapping.flow.table).values(
                mapping.flow.encodeEstablishedInsert({
                  evidence,
                  subjectId,
                  dedupUntil: record.absoluteExpiresAt,
                }),
              );
            } else if (store.pending !== undefined) {
              yield* store.pending.consumePending(pending, record.absoluteExpiresAt);
            }
            yield* current
              .insert(mapping.session.table)
              .values(
                mapping.session.encodeInsert(record, { subjectId, sessionId: nativeSessionId }),
              );
          }),
        rotate: (input, next) =>
          Effect.gen(function* () {
            const id = yield* mapping.sessionId.toNative(input.sessionId);

            yield* current
              .update(mapping.session.table)
              .set(mapping.session.encodeRotation(next))
              .where(
                and(
                  eq(sessionColumn("sessionId"), id),
                  eq(sessionColumn("digest"), input.expectedDigest),
                  eq(sessionColumn("version"), input.expectedVersion),
                ),
              );
          }),
        revokeDigest: (digest) =>
          Effect.asVoid(
            current.delete(mapping.session.table).where(eq(sessionColumn("digest"), digest)),
          ),
        revoke: (input) =>
          Effect.gen(function* () {
            const subjectId = yield* mapping.subjectId.toNative(input.subjectId);
            const sessionId = yield* mapping.sessionId.toNative(input.sessionId);

            yield* current
              .delete(mapping.session.table)
              .where(
                and(
                  eq(sessionColumn("subjectId"), subjectId),
                  eq(sessionColumn("sessionId"), sessionId),
                ),
              );
          }),
        revokeAll: (input, nextRevision) =>
          Effect.gen(function* () {
            const id = yield* mapping.subjectId.toNative(input.subjectId);

            yield* current
              .update(mapping.subject.table)
              .set(updateValues([[mapping.subject.securityRevision, nextRevision]]))
              .where(
                and(
                  eq(column(mapping.subject.table, mapping.subject.id), id),
                  eq(
                    column(mapping.subject.table, mapping.subject.securityRevision),
                    input.expectedSecurityRevision,
                  ),
                ),
              );
            yield* current.delete(mapping.session.table).where(eq(sessionColumn("subjectId"), id));
          }),
        readPage: (input) =>
          Effect.gen(function* () {
            const id = yield* mapping.subjectId.toNative(input.subjectId);

            const cursor =
              input.cursor === undefined
                ? undefined
                : yield* mapping.sessionId.toNative(
                    yield* Schema.decodeEffect(SessionId)(input.cursor),
                  );

            const now = mapping.session.encodeInstant(input.now);

            const rows = yield* current
              .select()
              .from(mapping.session.table)
              .where(
                and(
                  eq(sessionColumn("subjectId"), id),
                  eq(sessionColumn("securityRevision"), input.securityRevision),
                  gt(sessionColumn("expiresAt"), now),
                  gt(sessionColumn("absoluteExpiresAt"), now),
                  cursor === undefined ? undefined : gt(sessionColumn("sessionId"), cursor),
                ),
              )
              .orderBy(sessionColumn("sessionId"))
              .limit(input.limit);

            return yield* Effect.forEach(rows, (row) => mapping.session.decode(row));
          }),
      };

      return store;
    });

  const owner: SessionTransactionOwner<StatefulSessionStore<Claims>> = {
    read: yield* makeStore(database),
    isCurrent: Effect.map(
      Effect.serviceOption(CurrentSessionSql),
      (current) => Option.isSome(current) && current.value === database,
    ),
    transaction: (body) =>
      database.transaction((current) =>
        Effect.flatMap(makeStore(current), body).pipe(
          Effect.provideService(CurrentSessionSql, current),
        ),
      ),
  };

  return owner;
});
