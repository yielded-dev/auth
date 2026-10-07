import {
  type AnyEmailAddressMapping,
  type AnyProofPersistenceMapping,
  type EmailAddressStore,
  type EmailWorkflowOptions,
  type PersistenceOwner,
} from "@yielded/auth-persistence/Adapter";
import { and, eq, inArray, lte } from "drizzle-orm";
import { Effect } from "effect";

import { CurrentEmailSql, type EmailSqlConfiguration } from "./email-database";
import * as N from "./email-native";
import { NativeDatabase } from "./native-database";
import type { NativeSqlDatabase } from "./native-database";
import { CurrentProofSql } from "./proof-database";
import { completionSnapshot, proofCompletionStore } from "./proof-store";
import { readSnapshot } from "./sql-snapshot";

type Mapping = AnyEmailAddressMapping;

export const emailAddressStore = (
  mapping: Mapping,
  configuration: EmailSqlConfiguration,
  database: NativeSqlDatabase,
): EmailAddressStore => {
  const provided = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(CurrentEmailSql, database),
      Effect.provideService(CurrentProofSql, database),
    );

  const proof =
    configuration.proof === undefined
      ? undefined
      : proofCompletionStore(
          configuration.proof.mapping,
          configuration.proof.configuration,
          database,
        );

  return {
    ...(proof === undefined ? {} : { proof }),
    readAddress: (input, locking) =>
      provided(
        Effect.gen(function* () {
          const current = yield* N.currentAddress(mapping, input, locking, configuration, !locking);

          return current === undefined ? undefined : yield* N.addressTarget(current);
        }),
      ),
    readMutation: (input, action) =>
      provided(
        Effect.gen(function* () {
          const current = yield* N.currentAddress(
            mapping,
            {
              moduleId: input.moduleId,
              subjectId: input.captured.revision.subjectId,
              target: input.target,
              ...(input.captured.source === undefined
                ? {}
                : { sourceCredentialId: input.captured.source.credentialId }),
            },
            configuration.locking,
            configuration,
          );

          if (current === undefined) return undefined;

          return {
            target: yield* N.addressTarget(current),
            requirement: mapping.subject.decodeActionRequirement(current.subject, action),
            commandPresent:
              (yield* N.commandExists(
                mapping,
                input.moduleId,
                input.commandId,
                configuration.locking,
              )).length !== 0,
            applyMutation: (allocated, now) =>
              provided(N.applyMutation(mapping, input, action, current, allocated, now)),
          };
        }),
      ),
    readCompletion: (input) =>
      Effect.gen(function* () {
        if (configuration.proof === undefined || input.binding._tag !== "IdentifierChange")
          return yield* N.unavailable();
        const nativeSubjectId = yield* mapping.subjectId.toNative(input.binding.revision.subjectId);
        const authority = N.authorityReads(mapping, nativeSubjectId);

        const completion = yield* completionSnapshot(
          configuration.proof.mapping,
          configuration.proof.configuration,
          database,
          input,
          false,
        );

        const reads = [...authority, ...completion.reads];
        const snapshot = readSnapshot(database, reads, configuration.maxParameters);

        const rows = yield* snapshot.singleStatement
          ? snapshot.rows
          : database.transaction(
              (owner) => readSnapshot(owner, reads, configuration.maxParameters).rows,
            );

        return {
          revision: yield* N.addressRevision(mapping, nativeSubjectId, rows[0]?.[0], rows[1] ?? []),
          completion: yield* completion.decode(rows.slice(authority.length)),
        };
      }),
    readExpired: (input) =>
      Effect.gen(function* () {
        const c = N.commandColumns(mapping);

        const rows = yield* N.selectRows(
          database
            .select({ commandId: c.commandId })
            .from(mapping.command.table)
            .where(
              and(
                eq(c.moduleId, input.moduleId),
                lte(c.retentionUntil, mapping.encodeInstant(input.nowMillis)),
              ),
            )
            .limit(input.limit + 1),
          configuration.locking,
        );

        const selected = rows.slice(0, input.limit);

        return {
          result: { removed: selected.length, hasMore: rows.length > input.limit },
          deleteExpired:
            selected.length === 0
              ? Effect.void
              : database
                  .delete(mapping.command.table)
                  .where(
                    and(
                      eq(c.moduleId, input.moduleId),
                      inArray(
                        c.commandId,
                        selected.map((row) => row.commandId),
                      ),
                      lte(c.retentionUntil, mapping.encodeInstant(input.nowMillis)),
                    ),
                  )
                  .pipe(Effect.asVoid),
        };
      }),
  };
};

export const makeEmailOwner = (
  mapping: Mapping,
  configuration: EmailSqlConfiguration,
  nativeDatabase: object,
): PersistenceOwner<EmailAddressStore> => {
  const database = nativeDatabase as NativeSqlDatabase;

  return {
    read: emailAddressStore(mapping, configuration, database),
    transaction: (body) =>
      database.transaction((current) =>
        body(emailAddressStore(mapping, configuration, current)).pipe(
          Effect.provideService(CurrentEmailSql, current),
          Effect.provideService(CurrentProofSql, current),
        ),
      ),
  };
};

export const makeBackendEmailOwner = Effect.fnUntraced(function* (
  mapping: Mapping,
  options: EmailWorkflowOptions & { readonly maxParameters?: number },
  database: object,
  proofMapping?: AnyProofPersistenceMapping,
) {
  const native = yield* NativeDatabase;
  const mysql = native.$client.onDialectOrElse({ mysql: () => true, orElse: () => false });
  const { proof: _proof, ...settings } = options;

  const configuration: EmailSqlConfiguration = {
    ...settings,
    pgOrderedLocks: native.$client.onDialectOrElse({
      pg: () => options.locking,
      orElse: () => false,
    }),
    ...(proofMapping === undefined
      ? {}
      : {
          proof: {
            mapping: proofMapping,
            configuration: {
              ...settings,
              standaloneGuard: Effect.void,
              pgOrderedLocks: native.$client.onDialectOrElse({
                pg: () => options.locking,
                orElse: () => false,
              }),
              insertIfAbsent: (query, selfKey, selfValue) =>
                mysql
                  ? query.onDuplicateKeyUpdate({ set: { [selfKey]: selfValue } })
                  : query.onConflictDoNothing(),
            },
          },
        }),
  };

  return makeEmailOwner(mapping, configuration, database);
});
