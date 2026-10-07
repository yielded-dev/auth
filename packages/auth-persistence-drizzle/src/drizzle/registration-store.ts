import type {
  AnyPasswordPersistenceMapping,
  PasswordRegistrationStore,
  PersistenceOwner,
} from "@yielded/auth-persistence/Adapter";
import { PasswordUnavailable } from "@yielded/auth/Password";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { and, eq, sql, type Table } from "drizzle-orm";
import { Effect, Schema } from "effect";

import { column } from "./model";
import type { NativeSqlDatabase } from "./native-database";

export const makeRegistrationOwner = (
  mapping: AnyPasswordPersistenceMapping,
  receiptsTable: object,
  nativeDatabase: object,
) => {
  const database = nativeDatabase as NativeSqlDatabase;
  const receipts = receiptsTable as Table;

  const store = (current: NativeSqlDatabase): PasswordRegistrationStore => ({
    reserve: (input) =>
      current
        .insert(receipts)
        .values(input)
        .onConflictDoNothing()
        .returning({ reserved: sql`1` })
        .pipe(Effect.map((rows) => rows.length === 1)),
    identifierAvailable: (identifier) =>
      current
        .select({ present: sql`1` })
        .from(mapping.identifier.table)
        .where(
          and(
            eq(
              column(mapping.identifier.table, mapping.identifier.namespace),
              identifier.namespace,
            ),
            eq(column(mapping.identifier.table, mapping.identifier.value), identifier.value),
          ),
        )
        .limit(1)
        .pipe(Effect.map((rows) => rows.length === 0)),
    bindSubject: (input) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(input.subjectId);

        const rows = yield* current
          .select()
          .from(mapping.subject.table)
          .where(eq(column(mapping.subject.table, mapping.subject.id), native))
          .limit(1);

        const subject = rows[0];

        if (
          subject === undefined ||
          !mapping.subject.isActiveStatus(subject[mapping.subject.status])
        )
          return yield* PasswordUnavailable.make({});
        yield* Schema.decodeUnknownEffect(SecurityRevision)(
          subject[mapping.subject.securityRevision],
        );

        const bound = yield* current
          .insert(mapping.identifier.table)
          .values(
            mapping.identifier.encodeInitialInsert(
              input.identifier,
              native,
              input.identifierRevision,
            ),
          )
          .onConflictDoNothing()
          .returning({ bound: sql`1` });

        if (bound.length !== 1) return false;
        yield* current
          .insert(mapping.credential.table)
          .values(mapping.credential.encodeInsert({ ...input, subjectId: native }));
        yield* current.insert(mapping.authorityCredential.table).values(
          mapping.authorityCredential.encodeInsert({
            subjectId: native,
            credentialId: input.credentialId,
            revision: input.credentialRevision,
          }),
        );

        return true;
      }),
  });

  const owner: PersistenceOwner<PasswordRegistrationStore> = {
    read: store(database),
    transaction: (body) => database.transaction((current) => body(store(current))),
  };

  return Effect.succeed(owner);
};
