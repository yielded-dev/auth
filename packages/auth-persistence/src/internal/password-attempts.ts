import {
  coordinateCommit,
  CurrentCommitJournal,
  hasCommitScope,
  LifecycleHooks,
} from "@yielded/auth/Hooks";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import {
  type PasswordPersistence,
  PasswordUnavailable,
  snapshotPasswordCredential,
  type PasswordCredentialSnapshot,
  type PreparePasswordCommit,
  type PasswordAttemptAdmission,
} from "@yielded/auth/Password";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import { DateTime, Effect, Option, Redacted, Schema } from "effect";

import type { PersistenceMappingError } from "./mapping-error";
import type { AnyPasswordPersistenceMapping } from "./models/password-model";
import { sqlMapping, type SqlTable } from "./native-sql-table";
import type { PasswordSqlConfiguration } from "./password-kernel";
import { NativeDatabase } from "./transaction-kernel";

type Row = Readonly<Record<string, unknown>>;
type Mapping = AnyPasswordPersistenceMapping;

const unavailable = () => PasswordUnavailable.make({});
const nowMillis = DateTime.now.pipe(Effect.map(DateTime.toEpochMillis));

const failure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  reportPersistenceFailure(effect, Schema.is(PasswordUnavailable)).pipe(
    Effect.mapError(unavailable),
  );

export const samePasswordCredentialSnapshot = (
  a: PasswordCredentialSnapshot,
  b: PasswordCredentialSnapshot,
) =>
  a.moduleId === b.moduleId &&
  a.revision.subjectId === b.revision.subjectId &&
  a.revision.securityRevision === b.revision.securityRevision &&
  a.revision.credentials.length === b.revision.credentials.length &&
  a.revision.credentials.every((entry) =>
    b.revision.credentials.some(
      (other) => entry.credentialId === other.credentialId && entry.revision === other.revision,
    ),
  ) &&
  a.credentialId === b.credentialId &&
  a.credentialRevision === b.credentialRevision &&
  a.verifierVersion === b.verifierVersion &&
  Redacted.value(a.verifier) === Redacted.value(b.verifier) &&
  a.normalization === b.normalization &&
  a.identifier.namespace === b.identifier.namespace &&
  a.identifier.value === b.identifier.value &&
  a.identifierBindingRevision === b.identifierBindingRevision &&
  a.identifierVerifiedAtMillis === b.identifierVerifiedAtMillis;

/** The interactive attempt workflow uses the owning Effect SQL client directly.
 * Table adapters supply representation only; admission and settlement policy live here.
 */
export const makePasswordAttempts = Effect.fnUntraced(function* (
  table: (table: object) => SqlTable,
  mapping: Mapping,
  options: PasswordSqlConfiguration,
): Effect.fn.Return<
  Pick<PasswordPersistence["Service"], "prepareAttempt" | "settleAttempt">,
  PasswordUnavailable,
  LifecycleHooks | NativeDatabase
> {
  const sql = (yield* NativeDatabase).$client.withoutTransforms();
  const hooks = yield* LifecycleHooks;
  const parent = yield* Effect.serviceOption(CurrentCommitJournal);

  const [s, i, c, a] = yield* sqlMapping(
    () =>
      [
        table(mapping.subject.table),
        table(mapping.identifier.table),
        table(mapping.credential.table),
        table(mapping.attempt.table),
      ] as const,
  ).pipe(failure);

  const lock = options.locking ? sql.literal(" FOR UPDATE") : sql.literal("");

  const standalone = Effect.gen(function* () {
    if (options.coordinated) {
      const current = yield* Effect.serviceOption(CurrentCommitJournal);

      if (Option.isNone(parent) || Option.isNone(current) || parent.value !== current.value)
        return yield* unavailable();
    } else {
      if (yield* hasCommitScope) return yield* unavailable();
      yield* options.standaloneGuard;
    }
  });

  const owned = <A, E, R>(work: Effect.Effect<A, E, R>) =>
    standalone.pipe(
      Effect.andThen(coordinateCommit(() => sql.withTransaction(work), { mode: options.mode })),
      Effect.map((result) => result.value),
      Effect.provideService(LifecycleHooks, hooks),
      failure,
    );

  const allocate = <A>(
    asynchronous: Effect.Effect<A, PersistenceMappingError> | undefined,
    sync: (() => A) | undefined,
  ) => {
    if (options.mode !== "synchronous" && asynchronous !== undefined) return asynchronous;

    return sync === undefined
      ? Effect.fail(unavailable())
      : Effect.try({ try: sync, catch: unavailable });
  };

  // Bind each native ID through its own column codec. Physical encodings of the
  // same application ID need not match across subject, identifier and password.
  const snapshot = Effect.fnUntraced(function* (
    nativeId: unknown,
    moduleId: string,
    identifier: LoginIdentifier,
    locking: boolean,
    attemptId?: string,
  ) {
    const subjectTable = s.as("password_subject");
    const identifierTable = i.as("password_identifier");
    const credentialTable = c.as("password_credential");
    const attemptTable = a.as("password_attempt");

    const rows = yield* sqlMapping(
      () =>
        sql<Row>`select ${subjectTable.fields("subject_")}, ${identifierTable.fields("identifier_")}, ${credentialTable.fields("credential_")}
      ${attemptId === undefined ? sql.literal("") : sql`, ${attemptTable.fields("attempt_")}`}
      from ${subjectTable.name}
      inner join ${identifierTable.name} on ${identifierTable.column(mapping.identifier.namespace)} = ${identifierTable.value(mapping.identifier.namespace, identifier.namespace)}
        and ${identifierTable.column(mapping.identifier.value)} = ${identifierTable.value(mapping.identifier.value, identifier.value)}
        and ${identifierTable.column(mapping.identifier.subjectId)} = ${identifierTable.value(mapping.identifier.subjectId, nativeId)}
      inner join ${credentialTable.name} on ${credentialTable.column(mapping.credential.moduleId)} = ${credentialTable.value(mapping.credential.moduleId, moduleId)}
        and ${credentialTable.column(mapping.credential.subjectId)} = ${credentialTable.value(mapping.credential.subjectId, nativeId)}
      ${
        attemptId === undefined
          ? sql.literal("")
          : sql`inner join ${attemptTable.name} on
        ${attemptTable.column(mapping.attempt.moduleId)} = ${attemptTable.value(mapping.attempt.moduleId, moduleId)}
        and ${attemptTable.column(mapping.attempt.attemptId)} = ${attemptTable.value(mapping.attempt.attemptId, attemptId)}`
      }
      where ${subjectTable.column(mapping.subject.id)} = ${subjectTable.value(mapping.subject.id, nativeId)}
      ${locking ? lock : sql.literal("")}`,
    ).pipe(Effect.flatten);

    if (rows.length !== 1) return undefined;

    const [subject, identifierRow, credential] = yield* sqlMapping(
      () =>
        [
          s.decode(rows[0]!, "subject_"),
          i.decode(rows[0]!, "identifier_"),
          c.decode(rows[0]!, "credential_"),
        ] as const,
    );

    if (
      yield* sqlMapping(
        () =>
          !mapping.subject.isActiveStatus(subject[mapping.subject.status]) ||
          !mapping.identifier.isCurrent(identifierRow) ||
          !mapping.subjectId.equals(nativeId, identifierRow[mapping.identifier.subjectId]) ||
          !mapping.subjectId.equals(nativeId, subject[mapping.subject.id]) ||
          !mapping.subjectId.equals(nativeId, credential[mapping.credential.subjectId]),
      )
    )
      return undefined;

    const captured = yield* sqlMapping(() =>
      mapping.credential.decode({ moduleId, subject, identifier: identifierRow, credential }),
    ).pipe(Effect.flatten, Effect.flatMap(snapshotPasswordCredential));

    return {
      nativeId,
      captured,
      attempt:
        attemptId === undefined
          ? undefined
          : yield* sqlMapping(() => a.decode(rows[0]!, "attempt_")),
    };
  });

  const attemptRow = Effect.fnUntraced(function* (
    moduleId: string,
    attemptId: string,
    locking: boolean,
  ) {
    const rows = yield* sqlMapping(
      () => sql<Row>`select ${a.fields("a_")} from ${a.name}
      where ${a.column(mapping.attempt.moduleId)} = ${a.value(mapping.attempt.moduleId, moduleId)}
        and ${a.column(mapping.attempt.attemptId)} = ${a.value(mapping.attempt.attemptId, attemptId)}
      ${locking ? lock : sql.literal("")}`,
    ).pipe(Effect.flatten);

    return rows.length === 1 ? yield* sqlMapping(() => a.decode(rows[0]!, "a_")) : undefined;
  });

  const attemptMatches = (row: Row, candidate: PasswordCredentialSnapshot, nativeId: unknown) =>
    row[mapping.attempt.moduleId] === candidate.moduleId &&
    row[mapping.attempt.identifierNamespace] === candidate.identifier.namespace &&
    row[mapping.attempt.identifierValue] === candidate.identifier.value &&
    mapping.subjectId.equals(row[mapping.attempt.subjectId], nativeId) &&
    row[mapping.attempt.credentialId] === candidate.credentialId &&
    row[mapping.attempt.securityRevision] === candidate.revision.securityRevision &&
    row[mapping.attempt.credentialRevision] === candidate.credentialRevision &&
    row[mapping.attempt.verifierVersion] === candidate.verifierVersion &&
    row[mapping.attempt.identifierBindingRevision] === candidate.identifierBindingRevision;

  const service: Pick<PasswordPersistence["Service"], "prepareAttempt" | "settleAttempt"> = {
    // The remaining operations are composed by the persistence owner.
    prepareAttempt: (uncaptured) =>
      Effect.gen(function* () {
        const input = Object.freeze({
          ...uncaptured,
          identifier: Object.freeze({ ...uncaptured.identifier }),
        });

        yield* standalone;

        const identifiers = yield* sqlMapping(
          () => sql<Row>`select ${i.fields("i_")} from ${i.name}
        where ${i.column(mapping.identifier.namespace)} = ${i.value(mapping.identifier.namespace, input.identifier.namespace)}
          and ${i.column(mapping.identifier.value)} = ${i.value(mapping.identifier.value, input.identifier.value)}`,
        ).pipe(Effect.flatten);

        const identifier =
          identifiers.length === 1
            ? yield* sqlMapping(() => i.decode(identifiers[0]!, "i_"))
            : undefined;

        const resolved =
          identifier === undefined ||
          !(yield* sqlMapping(() => mapping.identifier.isCurrent(identifier)))
            ? undefined
            : yield* snapshot(
                identifier[mapping.identifier.subjectId],
                input.moduleId,
                input.identifier,
                false,
              );

        const candidate =
          resolved !== undefined &&
          (input.subjectId === undefined ||
            resolved.captured.revision.subjectId === input.subjectId)
            ? resolved
            : undefined;

        const attemptId = yield* allocate(mapping.allocateAttemptId, mapping.allocateAttemptIdSync);
        let used = false;

        return Object.freeze({
          ...(candidate === undefined ? {} : { credential: candidate.captured }),
          admit: <A>(prepare: PreparePasswordCommit<PasswordAttemptAdmission, A>) =>
            Effect.suspend(() => {
              if (used) return Effect.fail(unavailable());
              used = true;

              return owned(
                Effect.gen(function* () {
                  const journal = yield* CurrentCommitJournal;
                  const now = yield* nowMillis;
                  const captured = candidate?.captured;

                  // This receipt records what was inspected; it grants no authority.
                  // Settlement checks the current database against this exact snapshot.
                  yield* sqlMapping(
                    () =>
                      sql`${a.insert(
                        mapping.attempt.encodeInsert(
                          {
                            moduleId: input.moduleId,
                            action: input.action,
                            attemptId,
                            identifier: input.identifier,
                            ...(captured === undefined
                              ? {}
                              : {
                                  subjectId: captured.revision.subjectId,
                                  credentialId: captured.credentialId,
                                  securityRevision: captured.revision.securityRevision,
                                  credentialRevision: captured.credentialRevision,
                                  verifierVersion: captured.verifierVersion,
                                  identifierBindingRevision: captured.identifierBindingRevision,
                                }),
                            admittedAtMillis: now,
                            deadlineMillis: now + input.attemptLifetimeMillis,
                            retentionUntilMillis: now + input.attemptLifetimeMillis,
                          },
                          {
                            ...(candidate === undefined
                              ? {}
                              : { nativeSubjectId: candidate.nativeId }),
                            state: "pending",
                          },
                        ),
                      )}`,
                  ).pipe(Effect.flatten);

                  return prepare(
                    {
                      _tag: "Admitted",
                      attemptId,
                      ...(captured === undefined ? {} : { credential: captured }),
                    },
                    journal,
                  );
                }),
              );
            }),
        });
      }).pipe(failure),
    settleAttempt: (uncaptured, prepare) =>
      owned(
        Effect.gen(function* () {
          const input = Object.freeze({
            ...uncaptured,
            ...(uncaptured.rehash === undefined
              ? {}
              : { rehash: Object.freeze({ ...uncaptured.rehash }) }),
          });

          const journal = yield* CurrentCommitJournal;

          const captured =
            input.captured === undefined
              ? undefined
              : yield* snapshotPasswordCredential(input.captured);

          const discovered = yield* attemptRow(input.moduleId, input.attemptId, false);

          if (discovered === undefined || discovered[mapping.attempt.state] !== "pending")
            return prepare("rejected", journal);

          // Lock subject/identifier/password before the attempt, matching mutation order.
          const current =
            input.outcome !== "verified" || captured === undefined
              ? undefined
              : yield* snapshot(
                  discovered[mapping.attempt.subjectId],
                  input.moduleId,
                  captured.identifier,
                  true,
                );

          const row = yield* attemptRow(input.moduleId, input.attemptId, true);

          if (row === undefined || row[mapping.attempt.state] !== "pending")
            return prepare("rejected", journal);
          const now = yield* nowMillis;
          const deadline = yield* mapping.decodeInstant(row[mapping.attempt.deadline]);

          const verified =
            captured !== undefined &&
            current !== undefined &&
            captured.moduleId === input.moduleId &&
            deadline > now &&
            attemptMatches(row, captured, current.nativeId) &&
            samePasswordCredentialSnapshot(current.captured, captured);

          const decision = verified ? "verified" : "rejected";
          const receipt = prepare(decision, journal);

          yield* sqlMapping(
            () => sql`${a.update({ [mapping.attempt.state]: decision })}
        where ${a.column(mapping.attempt.moduleId)} = ${a.value(mapping.attempt.moduleId, input.moduleId)}
          and ${a.column(mapping.attempt.attemptId)} = ${a.value(mapping.attempt.attemptId, input.attemptId)}
          and ${a.column(mapping.attempt.state)} = ${a.value(mapping.attempt.state, "pending")}`,
          ).pipe(Effect.flatten);

          if (verified && current !== undefined && captured !== undefined) {
            let expected = current.captured;

            if (input.rehash !== undefined) {
              if (
                input.rehash.expectedVersion !== expected.verifierVersion ||
                Redacted.value(input.rehash.expectedVerifier) !== Redacted.value(expected.verifier)
              )
                return yield* unavailable();

              const version = yield* allocate(
                mapping.allocateRevision,
                mapping.allocateRevisionSync,
              );

              const rehash = input.rehash;

              yield* sqlMapping(
                () => sql`${c.update(mapping.credential.encodeVerifier(rehash.nextVerifier, version))}
            where ${c.column(mapping.credential.moduleId)} = ${c.value(mapping.credential.moduleId, input.moduleId)}
              and ${c.column(mapping.credential.subjectId)} = ${c.value(mapping.credential.subjectId, current.nativeId)}
              and ${c.column(mapping.credential.credentialId)} = ${c.value(mapping.credential.credentialId, captured.credentialId)}
              and ${c.column(mapping.credential.credentialRevision)} = ${c.value(mapping.credential.credentialRevision, captured.credentialRevision)}
              and ${c.column(mapping.credential.verifierVersion)} = ${c.value(mapping.credential.verifierVersion, rehash.expectedVersion)}
              and ${c.column(mapping.credential.verifier)} = ${c.value(mapping.credential.verifier, Redacted.value(rehash.expectedVerifier))}`,
              ).pipe(Effect.flatten);
              expected = {
                ...expected,
                verifierVersion: version,
                verifier: input.rehash.nextVerifier,
              };
            }

            const final = yield* snapshot(
              current.nativeId,
              input.moduleId,
              captured.identifier,
              false,
              input.attemptId,
            );

            if (
              final === undefined ||
              !samePasswordCredentialSnapshot(final.captured, expected) ||
              final.attempt === undefined ||
              final.attempt[mapping.attempt.state] !== "verified" ||
              !attemptMatches(final.attempt, captured, current.nativeId) ||
              (yield* mapping.decodeInstant(final.attempt[mapping.attempt.deadline])) !==
                deadline ||
              deadline <= (yield* nowMillis)
            )
              return yield* unavailable();
          }

          return receipt;
        }),
      ),
  };

  return service;
});
