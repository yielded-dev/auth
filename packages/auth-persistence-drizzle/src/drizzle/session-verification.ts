import {
  type SessionVerificationReader,
  type StatefulSessionMapping,
} from "@yielded/auth-persistence/Adapter";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { eq, getTableColumns, sql, type AnyColumn } from "drizzle-orm";
import { Effect, Schema } from "effect";

import { column } from "./model";
import { NativeDatabase } from "./native-database";
import { CurrentSessionSql } from "./session-database";
import { readSnapshot } from "./sql-snapshot";

/* oxlint-disable no-explicit-any -- the adapter validates native table/query shapes; domain records use mapped decoders. */
export const makeSessionVerificationReader = Effect.fnUntraced(function* <Claims>(
  mapping: StatefulSessionMapping<Claims, any, any, any, any, any, any, any>,
) {
  const database = yield* CurrentSessionSql;

  const dialect = (yield* NativeDatabase).$client.onDialectOrElse({
    pg: () => "pg" as const,
    sqlite: () => "sqlite" as const,
    orElse: () => undefined,
  });

  const reader: SessionVerificationReader<Claims> = {
    readForVerification: (digest) =>
      Effect.gen(function* () {
        const sessionSubject = column(mapping.session.table, mapping.session.subjectId);
        const sessionDigest = column(mapping.session.table, mapping.session.digest);
        const subjectId = column(mapping.subject.table, mapping.subject.id);

        const authority = (row: Record<string, unknown> | undefined) =>
          row === undefined
            ? Effect.succeed(undefined)
            : Effect.map(
                Schema.decodeUnknownEffect(SecurityRevision)(row[mapping.subject.securityRevision]),
                (securityRevision) => ({
                  active: mapping.subject.isActiveStatus(row[mapping.subject.status]),
                  securityRevision,
                }),
              );

        const pointRead = database.transaction((transaction) =>
          Effect.gen(function* () {
            const rows = yield* transaction
              .select()
              .from(mapping.session.table)
              .where(eq(sessionDigest, digest))
              .limit(1);

            const row = rows[0];

            if (row === undefined) return undefined;
            const record = yield* mapping.session.decode(row);
            const nativeSubjectId = yield* mapping.subjectId.toNative(record.subjectId);

            const subjects = yield* transaction
              .select()
              .from(mapping.subject.table)
              .where(eq(subjectId, nativeSubjectId))
              .limit(1);

            return { record, authority: yield* authority(subjects[0]) };
          }),
        );

        const compatible =
          dialect !== undefined &&
          !Object.hasOwn(getTableColumns(mapping.subject.table), "__auth_subject_id") &&
          !Object.hasOwn(getTableColumns(mapping.session.table), "__auth_session_subject") &&
          subjectId.getSQLType() === sessionSubject.getSQLType() &&
          (Reflect.get(subjectId, "dimensions") ?? 0) ===
            (Reflect.get(sessionSubject, "dimensions") ?? 0);

        const snapshot = compatible
          ? readSnapshot(
              database,
              [
                {
                  table: mapping.session.table,
                  where: eq(sessionDigest, digest),
                  limit: 1,
                  identities: { __auth_session_subject: sessionSubject },
                },
                {
                  table: mapping.subject.table,
                  identities: { __auth_subject_id: subjectId },
                  where: eq(
                    subjectId,
                    sql`(${database.select({ id: sessionSubject }).from(mapping.session.table).where(eq(sessionDigest, digest)).limit(1).getSQL()})`,
                  ),
                  limit: 1,
                },
              ],
              database.maxParameters,
            )
          : undefined;

        if (snapshot === undefined || !snapshot.singleStatement) return yield* pointRead;
        const [sessions, subjects] = yield* snapshot.rows;
        const row = sessions?.[0];

        if (row === undefined) return undefined;
        const { __auth_session_subject: rawOwner, ...sessionRow } = row;
        const record = yield* mapping.session.decode(sessionRow);
        const nativeSubjectId = yield* mapping.subjectId.toNative(record.subjectId);

        const binding = (target: AnyColumn, value: unknown) =>
          database
            .select({ value: sql`${sql.param(value, target)}` })
            .from(sql`(select 1) as session_binding`)
            .toSQL();

        const expected = binding(subjectId, nativeSubjectId);
        const native = expected.params[0];

        const scalar =
          typeof native === "string" ||
          typeof native === "boolean" ||
          typeof native === "bigint" ||
          (typeof native === "number" && Number.isFinite(native));

        const bare = scalar
          ? database
              .select({ value: sql`${native}` })
              .from(sql`(select 1) as session_binding`)
              .toSQL()
          : undefined;

        const stored = binding(sessionSubject, row[mapping.session.subjectId]);

        // Raw identity witnesses and the actual column bindings must agree with
        // the decoded owner. Opaque encoders and noncanonical stored IDs use the
        // decoded-owner transaction, preserving their native codec semantics.
        if (
          expected.params.length !== 1 ||
          bare === undefined ||
          expected.sql !== bare.sql ||
          rawOwner !== String(native) ||
          (subjects?.[0] !== undefined && subjects[0].__auth_subject_id !== String(native)) ||
          stored.sql !== expected.sql ||
          stored.params.length !== 1 ||
          stored.params[0] !== native
        )
          return yield* pointRead;

        return { record, authority: yield* authority(subjects?.[0]) };
      }),
  };

  return reader;
});
