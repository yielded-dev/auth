import { PasswordUnavailable } from "@yielded/auth/Password";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { Effect, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";

import type { AnyPasswordPersistenceMapping } from "./models/password-model";
import type { PersistenceOwner } from "./persistence-owner";
import type { PasswordRegistrationStore } from "./registration-store";
import {
  decodeSqlRow,
  requireSqlTable,
  sqlColumn,
  sqlInsert,
  sqlProjection,
  sqlTable,
  sqlValue,
} from "./sql-metadata";

export const makeSqlRegistrationOwner = (
  client: SqlClient,
  mapping: AnyPasswordPersistenceMapping,
  receiptsTable: object,
): PersistenceOwner<PasswordRegistrationStore> => {
  const sql = client.withoutTransforms();

  const receipts = requireSqlTable(receiptsTable),
    subjects = requireSqlTable(mapping.subject.table),
    identifiers = requireSqlTable(mapping.identifier.table),
    passwords = requireSqlTable(mapping.credential.table),
    credentials = requireSqlTable(mapping.authorityCredential.table);

  const store: PasswordRegistrationStore = {
    reserve: (input) =>
      sql`insert into ${sqlTable(sql, receipts)} ${sqlInsert(sql, receipts, input)} on conflict do nothing returning 1 as reserved`.pipe(
        Effect.map((rows) => rows.length === 1),
      ),
    identifierAvailable: (identifier) =>
      sql`select 1 as present from ${sqlTable(sql, identifiers)} where ${sqlColumn(sql, identifiers, mapping.identifier.namespace)}=${identifier.namespace} and ${sqlColumn(sql, identifiers, mapping.identifier.value)}=${identifier.value} limit 1`.pipe(
        Effect.map((rows) => rows.length === 0),
      ),
    bindSubject: (input) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(input.subjectId);

        const rows =
          yield* sql`select ${sqlProjection(sql, subjects)} from ${sqlTable(sql, subjects)} where ${sqlColumn(sql, subjects, mapping.subject.id)}=${sqlValue(sql, subjects, mapping.subject.id, native)} limit 1`;

        if (rows[0] === undefined) return yield* PasswordUnavailable.make({});
        const subject = yield* decodeSqlRow(subjects, rows[0]);

        if (!mapping.subject.isActiveStatus(subject[mapping.subject.status]))
          return yield* PasswordUnavailable.make({});
        yield* Schema.decodeUnknownEffect(SecurityRevision)(
          subject[mapping.subject.securityRevision],
        );

        const bound =
          yield* sql`insert into ${sqlTable(sql, identifiers)} ${sqlInsert(sql, identifiers, mapping.identifier.encodeInitialInsert(input.identifier, native, input.identifierRevision))} on conflict do nothing returning 1 as bound`;

        if (bound.length !== 1) return false;
        yield* sql`insert into ${sqlTable(sql, passwords)} ${sqlInsert(sql, passwords, mapping.credential.encodeInsert({ ...input, subjectId: native }))}`;
        yield* sql`insert into ${sqlTable(sql, credentials)} ${sqlInsert(sql, credentials, mapping.authorityCredential.encodeInsert({ subjectId: native, credentialId: input.credentialId, revision: input.credentialRevision }))}`;

        return true;
      }),
  };

  return {
    read: store,
    transaction: (body) => sql.withTransaction(body(store)),
  };
};
