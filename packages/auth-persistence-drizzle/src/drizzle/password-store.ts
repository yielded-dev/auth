import {
  type AnyPasswordPersistenceMapping,
  type AnyProofPersistenceMapping,
  type PasswordStore,
  type PasswordWorkflowOptions,
  type PersistenceOwner,
} from "@yielded/auth-persistence/Adapter";
import { snapshotPasswordCredential } from "@yielded/auth/Password";
import { and, eq, inArray } from "drizzle-orm";
import { Effect, Option } from "effect";

import { CurrentMutationTransaction, MutationPostconditions } from "./mutation-postconditions";
import { NativeDatabase } from "./native-database";
import type { NativeSqlDatabase } from "./native-database";
import { CurrentPasswordSql, type PasswordSqlConfiguration } from "./password-database";
import * as N from "./password-native";
import { CurrentProofSql } from "./proof-database";
import { completionSnapshot, proofCompletionStore } from "./proof-store";
import { readSnapshot, type SnapshotRead } from "./sql-snapshot";

type Mapping = AnyPasswordPersistenceMapping;
type Dialect = "pg" | "mysql" | "sqlite";

export const passwordStore = (
  mapping: Mapping,
  configuration: PasswordSqlConfiguration,
  database: NativeSqlDatabase,
  dialect: Dialect,
): PasswordStore => {
  const pgOrderedLocks = dialect === "pg" && configuration.locking;

  const provided = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(CurrentPasswordSql, database),
      Effect.provideService(CurrentProofSql, database),
    );

  const resolve = (input: Parameters<PasswordStore["readCredential"]>[0], locking: boolean) =>
    provided(
      N.resolveCredential(
        mapping,
        input.moduleId,
        input.identifier,
        input.subjectId,
        locking,
        !locking,
        configuration.maxParameters,
        pgOrderedLocks,
      ),
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
    readCredential: (input, locking) =>
      Effect.gen(function* () {
        const resolved = yield* resolve(input, locking);

        return resolved === undefined
          ? undefined
          : {
              subjectId: yield* mapping.subjectId.toSubject(resolved.nativeSubjectId),
              snapshot: resolved.snapshot,
            };
      }),
    readForSubject: (input) =>
      Effect.gen(function* () {
        const nativeSubjectId = yield* mapping.subjectId.toNative(input.subjectId);

        const s = N.subjectColumns(mapping),
          c = N.credentialColumns(mapping),
          i = N.identifierColumns(mapping);

        const reads = [
          { table: mapping.subject.table, where: eq(s.id, nativeSubjectId), limit: 1 },
          {
            table: mapping.credential.table,
            where: and(eq(c.moduleId, input.moduleId), eq(c.subjectId, nativeSubjectId)),
            limit: 1,
          },
          { table: mapping.identifier.table, where: eq(i.subjectId, nativeSubjectId) },
        ];

        const [subjects, credentials, identifiers] = yield* N.readRows(
          database,
          reads,
          false,
          configuration.maxParameters,
          false,
          true,
        );

        const subject = subjects?.[0],
          credential = credentials?.[0];

        const identifier = identifiers?.find((row) => mapping.identifier.isCurrent(row));

        if (
          subject === undefined ||
          !mapping.subject.isActiveStatus(subject[mapping.subject.status]) ||
          credential === undefined ||
          identifier === undefined
        )
          return undefined;

        return yield* mapping.credential
          .decode({ moduleId: input.moduleId, subject, identifier, credential })
          .pipe(Effect.flatMap(snapshotPasswordCredential));
      }),
    readMutation: (input, action) =>
      provided(
        Effect.gen(function* () {
          const nativeSubjectId = yield* mapping.subjectId.toNative(
            input.expectedRevision.subjectId,
          );

          const s = N.subjectColumns(mapping),
            i = N.identifierColumns(mapping),
            a = N.authorityCredentialColumns(mapping),
            c = N.credentialColumns(mapping),
            command = N.commandColumns(mapping);

          const expectedIds = [
            ...new Set(
              [
                ...input.expectedRevision.credentials,
                ...input.authorization.evidence.revision.credentials,
              ].map((item) => item.credentialId),
            ),
          ];

          const reads: SnapshotRead[] = [
            { table: mapping.subject.table, where: eq(s.id, nativeSubjectId), limit: 1 },
          ];

          const identifierIndex = reads.length;

          if (input.credential !== undefined)
            reads.push({
              table: mapping.identifier.table,
              where: and(
                eq(i.namespace, input.credential.identifier.namespace),
                eq(i.value, input.credential.identifier.value),
              ),
              limit: 1,
            });
          const authoritiesIndex = reads.length;

          reads.push({
            table: mapping.authorityCredential.table,
            where: and(eq(a.subjectId, nativeSubjectId), inArray(a.credentialId, expectedIds)),
            orderBy: [a.credentialId],
          });
          const passwordIndex = reads.length;

          reads.push({
            table: mapping.credential.table,
            where: and(eq(c.moduleId, input.moduleId), eq(c.subjectId, nativeSubjectId)),
            limit: 1,
          });
          const commandIndex = reads.length;

          reads.push({
            table: mapping.command.table,
            where: and(
              eq(command.moduleId, input.moduleId),
              eq(command.commandId, input.commandId),
            ),
            limit: 1,
          });

          const rows = yield* N.readRows(
            database,
            reads,
            configuration.locking,
            configuration.maxParameters,
            pgOrderedLocks,
          );

          const current = yield* N.readMutationAuthority(mapping, configuration, input, action, {
            nativeSubjectId,
            subject: rows[0]?.[0],
            identifier: input.credential === undefined ? undefined : rows[identifierIndex]?.[0],
            credentials: rows[authoritiesIndex] ?? [],
            password: rows[passwordIndex]?.[0],
          });

          return {
            ...current.facts,
            passwordPresent: current.credential !== undefined,
            expectedPasswordCurrent:
              current.credential !== undefined &&
              (yield* N.currentExpectedCredential(
                mapping,
                input,
                nativeSubjectId,
                current.credential,
              )),
            commandPresent: (rows[commandIndex]?.length ?? 0) !== 0,
            applyMutation: (revisions, commandNowMillis) =>
              provided(
                Effect.gen(function* () {
                  const changed = yield* action === "add-password"
                    ? N.writeAddition(mapping, input, nativeSubjectId, revisions, commandNowMillis)
                    : N.writeReplacement(
                        mapping,
                        input,
                        nativeSubjectId,
                        revisions,
                        commandNowMillis,
                      );

                  if (!changed) return yield* N.unavailable();

                  const postconditions = yield* Effect.serviceOption(MutationPostconditions);

                  if (Option.isSome(postconditions)) {
                    const check = Effect.flatMap(CurrentMutationTransaction, (owner) =>
                      Effect.gen(function* () {
                        if (
                          !(yield* N.checkMutationApplied(
                            mapping,
                            input,
                            nativeSubjectId,
                            revisions,
                            commandNowMillis,
                          ))
                        )
                          return yield* N.unavailable();
                      }).pipe(Effect.provideService(CurrentPasswordSql, owner), N.translateFailure),
                    );

                    if (!postconditions.value.register(check)) return yield* N.unavailable();
                  }

                  return true;
                }),
              ),
          };
        }),
      ),
    readReset: (input) =>
      Effect.gen(function* () {
        if (configuration.proof === undefined || input.binding._tag !== "Subject")
          return yield* N.unavailable();
        const binding = input.binding;

        const read = N.credentialRead(
          mapping,
          input.moduleId.slice(0, -"/reset".length),
          binding.identifier,
          yield* mapping.subjectId.toNative(binding.revision.subjectId),
          binding.revision.subjectId,
        );

        const completion = yield* completionSnapshot(
          configuration.proof.mapping,
          configuration.proof.configuration,
          database,
          input,
          false,
        );

        const reads = [...read.reads, ...completion.reads];
        const snapshot = readSnapshot(database, reads, configuration.maxParameters);

        const rows = yield* snapshot.singleStatement
          ? snapshot.rows
          : database.transaction(
              (owner) => readSnapshot(owner, reads, configuration.maxParameters).rows,
            );

        return {
          credential: (yield* read.current(rows.slice(0, read.reads.length)))?.snapshot,
          completion: yield* completion.decode(rows.slice(read.reads.length)),
        };
      }),
  };
};

export const makePasswordOwner = Effect.fnUntraced(function* (
  mapping: Mapping,
  configuration: PasswordSqlConfiguration,
  nativeDatabase: object,
) {
  const database = nativeDatabase as NativeSqlDatabase;

  const dialect = (yield* NativeDatabase).$client.onDialectOrElse({
    pg: () => "pg" as const,
    mysql: () => "mysql" as const,
    orElse: () => "sqlite" as const,
  });

  const owner: PersistenceOwner<PasswordStore> = {
    read: passwordStore(mapping, configuration, database, dialect),
    transaction: (body) =>
      database.transaction((current) =>
        body(passwordStore(mapping, configuration, current, dialect)).pipe(
          Effect.provideService(CurrentPasswordSql, current),
          Effect.provideService(CurrentProofSql, current),
        ),
      ),
  };

  return owner;
});

export const makeBackendPasswordOwner = Effect.fnUntraced(function* (
  mapping: Mapping,
  options: PasswordWorkflowOptions & { readonly maxParameters?: number },
  database: object,
  proofMapping?: AnyProofPersistenceMapping,
) {
  const native = yield* NativeDatabase;
  const mysql = native.$client.onDialectOrElse({ mysql: () => true, orElse: () => false });

  const configuration: PasswordSqlConfiguration = {
    mode: options.mode,
    locking: options.locking,
    standaloneGuard: options.standaloneGuard,
    ...(options.coordinated === undefined ? {} : { coordinated: options.coordinated }),
    ...(options.maxParameters === undefined ? {} : { maxParameters: options.maxParameters }),
    ...(proofMapping === undefined
      ? {}
      : {
          proof: {
            mapping: proofMapping,
            configuration: {
              mode: options.mode,
              locking: options.locking,
              standaloneGuard: Effect.void,
              ...(options.coordinated === undefined ? {} : { coordinated: options.coordinated }),
              ...(options.maxParameters === undefined
                ? {}
                : { maxParameters: options.maxParameters }),
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
    insertIfAbsent: (query, selfKey, selfValue) =>
      mysql
        ? query.onDuplicateKeyUpdate({ set: { [selfKey]: selfValue } })
        : query.onConflictDoNothing(),
  };

  return yield* makePasswordOwner(mapping, configuration, database);
});
