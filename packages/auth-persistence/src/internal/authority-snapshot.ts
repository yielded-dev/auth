import type { SubjectId } from "@yielded/auth/Schema";
import { AuthenticationRevision, StaleAuthentication } from "@yielded/auth/Sessions";
import { Effect, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";

import type { SessionAuthorityTables } from "./models/session-model";
import { sqlMapping, type NativeSqlTables } from "./native-sql-table";
import type { AnyTableModel } from "./query-operations";

/** One statement gives preflight a coherent view without opening a transaction.
 * Commit-time authority checks still lock and revalidate in the persistence owner.
 */
export const makeAuthoritySnapshot = (
  sql: SqlClient,
  tables: NativeSqlTables,
  mapping: SessionAuthorityTables<AnyTableModel, AnyTableModel, unknown>,
) =>
  Effect.fnUntraced(function* (subjectId: SubjectId, credentialIds: ReadonlyArray<string>) {
    if (new Set(credentialIds).size !== credentialIds.length)
      return yield* StaleAuthentication.make({});

    const { s, c } = yield* sqlMapping(() => ({
      s: tables(mapping.subject.table).as("auth_subject"),
      c: tables(mapping.credential.table).as("auth_credential"),
    }));

    const nativeId = yield* sqlMapping(() => mapping.subjectId.toNative(subjectId)).pipe(
      Effect.flatten,
    );

    const requested = [...credentialIds].sort((a, b) => a.localeCompare(b));

    const rows = yield* sqlMapping(
      () => sql<Record<string, unknown>>`select ${s.fields("s_")}
      ${requested.length === 0 ? sql.literal("") : sql`, ${c.fields("c_")}`}
      from ${s.name}
      ${
        requested.length === 0
          ? sql.literal("")
          : sql`inner join ${c.name} on
        ${c.column(mapping.credential.subjectId)} = ${c.value(mapping.credential.subjectId, nativeId)}
        and ${sql.or(requested.map((id) => sql`${c.column(mapping.credential.credentialId)} = ${c.value(mapping.credential.credentialId, id)}`))}`
      }
      where ${s.column(mapping.subject.id)} = ${s.value(mapping.subject.id, nativeId)}`,
    ).pipe(Effect.flatten);

    const first = rows[0];

    if (first === undefined || rows.length !== Math.max(1, requested.length))
      return yield* StaleAuthentication.make({});

    const subject = yield* sqlMapping(() => s.decode(first, "s_"));

    if (!(yield* sqlMapping(() => mapping.subject.isActiveStatus(subject[mapping.subject.status]))))
      return yield* StaleAuthentication.make({});

    const credentials = yield* sqlMapping(() =>
      requested.length === 0 ? [] : rows.map((row) => c.decode(row, "c_")),
    );

    if (
      yield* sqlMapping(() =>
        credentials.some(
          (row) =>
            mapping.credential.status !== undefined &&
            mapping.credential.isActiveStatus?.(row[mapping.credential.status]) !== true,
        ),
      )
    )
      return yield* StaleAuthentication.make({});

    const revision = yield* Schema.decodeUnknownEffect(AuthenticationRevision)({
      subjectId,
      securityRevision: subject[mapping.subject.securityRevision],
      credentials: credentials.map((row) => ({
        credentialId: row[mapping.credential.credentialId],
        revision: row[mapping.credential.revision],
      })),
    });

    const sorted = [...revision.credentials].sort((a, b) =>
      a.credentialId.localeCompare(b.credentialId),
    );

    if (sorted.some((item, index) => item.credentialId !== requested[index]))
      return yield* StaleAuthentication.make({});

    return { subject, revision: { ...revision, credentials: sorted } };
  });
