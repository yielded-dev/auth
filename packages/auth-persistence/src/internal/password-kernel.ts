import {
  coordinateCommit,
  CurrentCommitJournal,
  hasCommitScope,
  type CommitJournal,
  type PreparedCommit,
  LifecycleHooks,
  HookConfigurationError,
} from "@yielded/auth/Hooks";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import {
  PasswordUnavailable,
  PasswordPersistence,
  type PasswordMutationInput,
  snapshotPasswordCredential,
  snapshotPasswordRequirement,
  snapshotPasswordRevision,
  type PasswordAction,
  type PasswordMutationDecision,
} from "@yielded/auth/Password";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import {
  type ProofCompletionPlan,
  type ProofCompletionInput,
  ProofUnavailable,
} from "@yielded/auth/Proofs";
import {
  snapshotAuthenticationEvidence,
  type AuthenticationEvidence,
  type AuthenticationRequirement,
  type SecurityRevision,
} from "@yielded/auth/Sessions";
import { Cause, Context, DateTime, Effect, Option, Redacted, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";
import type * as SqlError from "effect/sql/SqlError";

import { PersistenceMappingError } from "./mapping-error";
import {
  type AnyPasswordPersistenceMapping,
  requiredPasswordConstraints,
} from "./models/password-model";
import { makeNativeSqlTables, sqlMapping, type NativeSqlTables } from "./native-sql-table";
import {
  makePasswordAttempts,
  samePasswordCredentialSnapshot as sameCredentialSnapshot,
} from "./password-attempts";
import {
  CurrentPasswordPreparedTransaction,
  PasswordPreparedPostconditions,
} from "./PasswordPreparedPostconditions";
import {
  CurrentProofSql,
  type ProofSqlConfiguration,
  type ProofSqlDatabase,
  type makeProofKernel,
} from "./proof-kernel";
/* oxlint-disable no-explicit-any -- existing storage kernels erase foreign table shapes; domain errors remain typed. */
import type { QueryFailure } from "./query-operations";
import type { QueryOperations, SqlFragment, SqlColumn } from "./query-operations";
import { NativeDatabase } from "./transaction-kernel";

type AdapterFailure = QueryFailure | PersistenceMappingError | SqlError.SqlError;

export interface PasswordSqlQuery<A = ReadonlyArray<any>> extends Effect.Effect<A, AdapterFailure> {
  readonly getSQL: () => ReturnType<QueryOperations["sql"]>;
  readonly from: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly where: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly limit: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly orderBy: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly for: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly set: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly values: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly returning: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly $returningId: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly onConflictDoNothing: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
  readonly onDuplicateKeyUpdate: (...args: ReadonlyArray<any>) => PasswordSqlQuery<A>;
}

export interface PasswordSqlDatabase {
  readonly select: (...args: ReadonlyArray<any>) => PasswordSqlQuery;
  readonly insert: (...args: ReadonlyArray<any>) => PasswordSqlQuery;
  readonly update: (...args: ReadonlyArray<any>) => PasswordSqlQuery;
  readonly delete: (...args: ReadonlyArray<any>) => PasswordSqlQuery;
  readonly transaction: <A, E, R>(
    body: (transaction: PasswordSqlDatabase) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | SqlError.SqlError, R>;
}

export class CurrentPasswordSql extends Context.Service<CurrentPasswordSql, PasswordSqlDatabase>()(
  "effect-auth/CurrentPasswordSql",
) {}

export interface PasswordSqlConfiguration {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly standaloneGuard: Effect.Effect<void, PasswordUnavailable>;
  readonly coordinated?: boolean;
  readonly insertIfAbsent: (
    query: PasswordSqlQuery,
    selfKey: string,
    selfValue: unknown,
  ) => PasswordSqlQuery;
  readonly proof?: {
    readonly mapping: any;
    readonly configuration: ProofSqlConfiguration;
  };
}

type Database = PasswordSqlDatabase;

export const makePasswordKernel = <
  Fragment extends SqlFragment = SqlFragment,
  Column extends SqlColumn = SqlColumn,
>(
  operations: QueryOperations<Fragment, Column>,
  proofs: Pick<ReturnType<typeof makeProofKernel>, "completeProofPlanIn">,
  nativeTables: (client: SqlClient, database: object) => NativeSqlTables = (client) =>
    makeNativeSqlTables(client),
) => {
  type Mapping = AnyPasswordPersistenceMapping<Fragment>;

  const { and, eq, inArray, lte, column, updateValues } = operations;
  const { completeProofPlanIn } = proofs;
  const unavailable = () => PasswordUnavailable.make({});

  const translateFailure = <A, E, R>(
    effect: Effect.Effect<A, E, R>,
  ): Effect.Effect<A, PasswordUnavailable, R> =>
    reportPersistenceFailure(
      effect,
      (error) =>
        Schema.is(PasswordUnavailable)(error) ||
        Schema.is(ProofUnavailable)(error) ||
        Schema.is(HookConfigurationError)(error),
    ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, () => unavailable()))));

  const nowMillis = DateTime.now.pipe(Effect.map(DateTime.toEpochMillis));

  const validConstraints = (mapping: Mapping) =>
    Object.entries(requiredPasswordConstraints).every(
      ([key, value]) =>
        mapping.constraints[key as keyof typeof requiredPasswordConstraints] === value,
    );

  const selectRows = (query: PasswordSqlQuery, locking: boolean) =>
    locking && typeof query.for === "function" ? query.for("update") : query;

  const subjectColumns = (mapping: Mapping) => ({
    id: column(mapping.subject.table, mapping.subject.id),
    status: column(mapping.subject.table, mapping.subject.status),
    securityRevision: column(mapping.subject.table, mapping.subject.securityRevision),
  });

  const identifierColumns = (mapping: Mapping) => ({
    namespace: column(mapping.identifier.table, mapping.identifier.namespace),
    value: column(mapping.identifier.table, mapping.identifier.value),
    subjectId: column(mapping.identifier.table, mapping.identifier.subjectId),
    verifiedAt: column(mapping.identifier.table, mapping.identifier.verifiedAt),
    bindingRevision: column(mapping.identifier.table, mapping.identifier.bindingRevision),
  });

  const credentialColumns = (mapping: Mapping) => ({
    moduleId: column(mapping.credential.table, mapping.credential.moduleId),
    subjectId: column(mapping.credential.table, mapping.credential.subjectId),
    credentialId: column(mapping.credential.table, mapping.credential.credentialId),
    credentialRevision: column(mapping.credential.table, mapping.credential.credentialRevision),
    verifierVersion: column(mapping.credential.table, mapping.credential.verifierVersion),
    verifier: column(mapping.credential.table, mapping.credential.verifier),
    normalization: column(mapping.credential.table, mapping.credential.normalization),
  });

  const authorityCredentialColumns = (mapping: Mapping) => ({
    subjectId: column(mapping.authorityCredential.table, mapping.authorityCredential.subjectId),
    credentialId: column(
      mapping.authorityCredential.table,
      mapping.authorityCredential.credentialId,
    ),
    revision: column(mapping.authorityCredential.table, mapping.authorityCredential.revision),
  });

  const attemptColumns = (mapping: Mapping) => ({
    moduleId: column(mapping.attempt.table, mapping.attempt.moduleId),
    action: column(mapping.attempt.table, mapping.attempt.action),
    attemptId: column(mapping.attempt.table, mapping.attempt.attemptId),
    identifierNamespace: column(mapping.attempt.table, mapping.attempt.identifierNamespace),
    identifierValue: column(mapping.attempt.table, mapping.attempt.identifierValue),
    subjectId: column(mapping.attempt.table, mapping.attempt.subjectId),
    credentialId: column(mapping.attempt.table, mapping.attempt.credentialId),
    securityRevision: column(mapping.attempt.table, mapping.attempt.securityRevision),
    credentialRevision: column(mapping.attempt.table, mapping.attempt.credentialRevision),
    verifierVersion: column(mapping.attempt.table, mapping.attempt.verifierVersion),
    identifierBindingRevision: column(
      mapping.attempt.table,
      mapping.attempt.identifierBindingRevision,
    ),
    admittedAt: column(mapping.attempt.table, mapping.attempt.admittedAt),
    deadline: column(mapping.attempt.table, mapping.attempt.deadline),
    retentionUntil: column(mapping.attempt.table, mapping.attempt.retentionUntil),
    state: column(mapping.attempt.table, mapping.attempt.state),
  });

  const commandColumns = (mapping: Mapping) => ({
    moduleId: column(mapping.command.table, mapping.command.moduleId),
    commandId: column(mapping.command.table, mapping.command.commandId),
    action: column(mapping.command.table, mapping.command.action),
    bindingDigest: column(mapping.command.table, mapping.command.bindingDigest),
    decision: column(mapping.command.table, mapping.command.decision),
    retentionUntil: column(mapping.command.table, mapping.command.retentionUntil),
  });

  const allocate = <A>(
    mode: PasswordSqlConfiguration["mode"],
    asyncValue: Effect.Effect<A, PersistenceMappingError> | undefined,
    syncValue: (() => A) | undefined,
  ): Effect.Effect<A, PasswordUnavailable | PersistenceMappingError> => {
    if (mode === "synchronous")
      return syncValue === undefined
        ? Effect.fail(unavailable())
        : Effect.try({
            try: syncValue,
            catch: (cause) => new PersistenceMappingError({ operation: "mapping", cause }),
          });
    if (asyncValue !== undefined) return asyncValue;

    return syncValue === undefined
      ? Effect.fail(unavailable())
      : Effect.try({
          try: syncValue,
          catch: (cause) => new PersistenceMappingError({ operation: "mapping", cause }),
        });
  };

  const allocateNextSecurityRevision = (
    mapping: Mapping,
    mode: PasswordSqlConfiguration["mode"],
    current: SecurityRevision,
  ) => {
    const asyncValue = mapping.subject.nextSecurityRevision?.(current);

    const syncValue =
      mapping.subject.nextSecurityRevisionSync === undefined
        ? undefined
        : () => mapping.subject.nextSecurityRevisionSync!(current);

    return allocate(
      mode,
      asyncValue ?? mapping.allocateRevision,
      syncValue ?? mapping.allocateRevisionSync,
    );
  };

  const sameIdentifier = (left: LoginIdentifier, right: LoginIdentifier) =>
    left.namespace === right.namespace && left.value === right.value;

  const evidenceSatisfiedAt = (
    evidence: AuthenticationEvidence,
    requirement: AuthenticationRequirement,
    now: number,
  ): boolean => {
    if (evidence.proofs.length > 64 || evidence.revision.credentials.length > 64) return false;
    const revisions = new Map<string, string>();

    for (const item of evidence.revision.credentials) {
      if (revisions.has(item.credentialId)) return false;
      revisions.set(item.credentialId, item.revision);
    }
    if (evidence.proofs.some((proof) => !revisions.has(proof.credentialId))) return false;
    if (evidence.proofs.some((proof) => now < DateTime.toEpochMillis(proof.verifiedAt)))
      return false;

    const eligible = evidence.proofs.filter((proof) => {
      const age = now - DateTime.toEpochMillis(proof.verifiedAt);

      return age >= 0 && age < requirement.maximumAgeMillis;
    });

    const factors = new Set(eligible.flatMap((proof) => proof.factors));
    const credentials = new Set(eligible.map((proof) => proof.credentialId));

    return requirement.alternatives.some(
      (alternative) =>
        alternative.factors.every((factor) => factors.has(factor)) &&
        credentials.size >= alternative.minimumCredentials &&
        eligible.some(
          (proof) =>
            (!alternative.userVerified || proof.userVerified) &&
            (!alternative.phishingResistant || proof.phishingResistant),
        ),
    );
  };

  const snapshotMutationInput = Effect.fn("DrizzlePassword.snapshotMutationInput")(function* (
    input: PasswordMutationInput,
  ) {
    const expectedRevision = snapshotPasswordRevision(input.expectedRevision);

    const evidence = yield* snapshotAuthenticationEvidence(input.authorization.evidence).pipe(
      Effect.mapError(unavailable),
    );

    const requirement = yield* snapshotPasswordRequirement(input.authorization.requirement);

    const credential =
      input.credential === undefined
        ? undefined
        : yield* snapshotPasswordCredential(input.credential);

    return Object.freeze({
      ...input,
      expectedRevision,
      replacement: Object.freeze({
        verifier: Redacted.make(Redacted.value(input.replacement.verifier)),
        normalization: input.replacement.normalization,
      }),
      invalidation: Object.freeze({ ...input.invalidation }),
      ...(credential === undefined ? {} : { credential }),
      authorization: Object.freeze({
        challenge: Object.freeze({
          ...input.authorization.challenge,
          revision: snapshotPasswordRevision(input.authorization.challenge.revision),
        }),
        evidence,
        requirement,
      }),
    });
  });

  const lockSubject = Effect.fn("DrizzlePassword.lockSubject")(function* (
    mapping: Mapping,
    subjectId: string,
    locking: boolean,
  ) {
    const database = yield* CurrentPasswordSql;

    const nativeSubjectId = yield* mapping.subjectId.toNative(subjectId as any);
    const c = subjectColumns(mapping);

    const rows = yield* selectRows(
      database.select().from(mapping.subject.table).where(eq(c.id, nativeSubjectId)).limit(1),
      locking,
    );

    return { nativeSubjectId, row: rows[0] };
  });

  const lockIdentifier = Effect.fn("Drizzle.lockIdentifier")(function* (
    mapping: Mapping,
    identifier: LoginIdentifier,
    locking: boolean,
  ) {
    const database = yield* CurrentPasswordSql;

    const c = identifierColumns(mapping);

    return yield* selectRows(
      database
        .select()
        .from(mapping.identifier.table)
        .where(and(eq(c.namespace, identifier.namespace), eq(c.value, identifier.value)))
        .limit(1),
      locking,
    );
  });

  const readPasswordCredential = Effect.fn("Drizzle.readPasswordCredential")(function* (
    mapping: Mapping,
    moduleId: string,
    nativeSubjectId: unknown,
    locking: boolean,
  ) {
    const database = yield* CurrentPasswordSql;

    const c = credentialColumns(mapping);

    return yield* selectRows(
      database
        .select()
        .from(mapping.credential.table)
        .where(and(eq(c.moduleId, moduleId), eq(c.subjectId, nativeSubjectId)))
        .limit(1),
      locking,
    );
  });

  const resolveCredential = Effect.fn("DrizzlePassword.resolveCredential")(function* (
    mapping: Mapping,
    moduleId: string,
    identifier: LoginIdentifier,
    requestedSubjectId: string | undefined,
    locking: boolean,
  ) {
    const database = yield* CurrentPasswordSql;

    // The unlocked lookup only discovers the prospective subject. The canonical
    // protected order starts with the subject and then rechecks the identifier.
    const discovered = (yield* lockIdentifier(mapping, identifier, false))[0];

    if (discovered === undefined || !mapping.identifier.isCurrent(discovered)) return undefined;
    const discoveredNative = discovered[mapping.identifier.subjectId];

    const subjectRows = yield* selectRows(
      database
        .select()
        .from(mapping.subject.table)
        .where(eq(subjectColumns(mapping).id, discoveredNative))
        .limit(1),
      locking,
    );

    const subject = subjectRows[0];

    if (subject === undefined || !mapping.subject.isActiveStatus(subject[mapping.subject.status]))
      return undefined;
    const identifiers = yield* lockIdentifier(mapping, identifier, locking);
    const identifierRow = identifiers[0];

    if (
      identifierRow === undefined ||
      !mapping.identifier.isCurrent(identifierRow) ||
      !mapping.subjectId.equals(discoveredNative, identifierRow[mapping.identifier.subjectId])
    )
      return undefined;
    const subjectId = yield* mapping.subjectId.toSubject(discoveredNative);

    if (requestedSubjectId !== undefined && requestedSubjectId !== subjectId) return undefined;
    const credentials = yield* readPasswordCredential(mapping, moduleId, discoveredNative, locking);
    const credential = credentials[0];

    if (credential === undefined)
      return { nativeSubjectId: discoveredNative, subject, identifier: identifierRow };

    const snapshot = yield* mapping.credential
      .decode({ moduleId, subject, identifier: identifierRow, credential })
      .pipe(Effect.flatMap(snapshotPasswordCredential));

    return {
      nativeSubjectId: discoveredNative,
      subject,
      identifier: identifierRow,
      credential,
      snapshot,
    };
  });

  const owned = <A, E, R>(
    database: Database,
    mapping: Mapping,
    configuration: PasswordSqlConfiguration,
    body: Effect.Effect<A, E, R>,
  ) => {
    if (!validConstraints(mapping)) return Effect.fail(unavailable());

    const run = coordinateCommit(
      () =>
        database.transaction((transaction) =>
          body.pipe(
            Effect.provideService(CurrentPasswordSql, transaction),
            Effect.provideService(CurrentProofSql, transaction as unknown as ProofSqlDatabase),
          ),
        ),
      { mode: configuration.mode },
    ).pipe(Effect.map((result) => result.value));

    return configuration.coordinated !== true
      ? Effect.gen(function* () {
          if (yield* hasCommitScope) return yield* unavailable();
          yield* configuration.standaloneGuard;

          return yield* run;
        })
      : run;
  };

  // A coordinator that accepts postconditions re-runs this check against its
  // current transaction after application work, before commit.
  const registerFinal = Effect.fnUntraced(function* <E>(
    check: Effect.Effect<boolean, E, CurrentPasswordSql>,
  ) {
    const postconditions = yield* Effect.serviceOption(PasswordPreparedPostconditions);

    if (Option.isNone(postconditions)) return;

    const postcondition = Effect.gen(function* () {
      const transaction = yield* CurrentPasswordPreparedTransaction;

      if (!(yield* check.pipe(Effect.provideService(CurrentPasswordSql, transaction))))
        return yield* unavailable();
    }).pipe(translateFailure);

    if (!postconditions.value.register(postcondition)) return yield* unavailable();
  });

  const safeRead = <A, E, R>(
    database: Database,
    configuration: PasswordSqlConfiguration,
    body: Effect.Effect<A, E, R>,
  ) =>
    Effect.gen(function* () {
      if (configuration.coordinated !== true) {
        if (yield* hasCommitScope) return yield* unavailable();
        yield* configuration.standaloneGuard;
      }

      return yield* database.transaction((transaction) =>
        body.pipe(
          Effect.provideService(CurrentPasswordSql, transaction),
          Effect.provideService(CurrentProofSql, transaction as unknown as ProofSqlDatabase),
        ),
      );
    });

  const proofCompletionMatchesPassword = (
    input: PasswordMutationInput & { readonly completion: ProofCompletionPlan },
  ) => {
    const completion = input.completion.input;
    const binding = completion.binding;

    if (
      completion.moduleId !== `${input.moduleId}/reset` ||
      completion.purpose !== "password-reset" ||
      binding._tag !== "Subject" ||
      input.credential === undefined ||
      binding.revision.subjectId !== input.expectedRevision.subjectId ||
      binding.revision.securityRevision !== input.expectedRevision.securityRevision ||
      !sameIdentifier(binding.identifier, input.credential.identifier)
    )
      return false;

    const expected = [...input.expectedRevision.credentials].sort((left, right) =>
      left.credentialId.localeCompare(right.credentialId),
    );

    const actual = [...binding.revision.credentials].sort((left, right) =>
      left.credentialId.localeCompare(right.credentialId),
    );

    return (
      expected.length === actual.length &&
      expected.every(
        (item, index) =>
          item.credentialId === actual[index]!.credentialId &&
          item.revision === actual[index]!.revision,
      )
    );
  };

  const probeProofCompletion = Effect.fn("Drizzle.probeProofCompletion")(function* (
    configuration: PasswordSqlConfiguration,
    input: ProofCompletionInput,
  ) {
    const database = yield* CurrentPasswordSql;

    if (configuration.proof === undefined) return yield* Effect.fail(unavailable());
    const validProbe = { _tag: "PasswordProofCompletionValid" } as const;

    const plan: ProofCompletionPlan = {
      input,
      prepare: (decision, journal, project) => journal.prepare(project(decision)),
    };

    const probe = coordinateCommit(
      () =>
        database.transaction((transaction) =>
          completeProofPlanIn(
            configuration.proof!.mapping,
            configuration.proof!.configuration,
            plan,
            Effect.fail(validProbe),
            () => false,
          ).pipe(
            Effect.provideService(CurrentProofSql, transaction as unknown as ProofSqlDatabase),
          ),
        ),
      { mode: configuration.mode },
    );

    if (configuration.coordinated === true || (yield* hasCommitScope)) return yield* unavailable();
    yield* configuration.standaloneGuard;

    return yield* probe.pipe(
      Effect.as(false),
      Effect.catchCause((cause) => {
        const reason = cause.reasons[0];

        return cause.reasons.length === 1 &&
          reason !== undefined &&
          Cause.isFailReason(reason) &&
          reason.error === validProbe
          ? Effect.succeed(true)
          : Effect.failCause(cause);
      }),
    );
  });

  const validateMutationAuthority = Effect.fn("DrizzlePassword.validateMutationAuthority")(
    function* (
      mapping: Mapping,
      configuration: PasswordSqlConfiguration,
      input: PasswordMutationInput,
      action: PasswordAction,
    ) {
      const database = yield* CurrentPasswordSql;

      const locked = yield* lockSubject(
        mapping,
        input.expectedRevision.subjectId,
        configuration.locking,
      );

      const row = locked.row;

      if (
        row === undefined ||
        !mapping.subject.isActiveStatus(row[mapping.subject.status]) ||
        row[mapping.subject.securityRevision] !== input.expectedRevision.securityRevision
      )
        return undefined;
      if (
        input.authorization.challenge.moduleId !== input.moduleId ||
        input.authorization.challenge.action !== action ||
        input.authorization.challenge.commandId !== input.commandId ||
        input.authorization.challenge.revision.subjectId !== input.expectedRevision.subjectId ||
        input.authorization.challenge.revision.securityRevision !==
          input.expectedRevision.securityRevision ||
        (input.authorization.evidence.flowId as string) !== (input.commandId as string) ||
        input.authorization.evidence.bindingDigest !==
          input.authorization.challenge.bindingDigest ||
        input.authorization.evidence.revision.subjectId !== input.expectedRevision.subjectId ||
        input.authorization.evidence.revision.securityRevision !==
          input.expectedRevision.securityRevision ||
        (action === "add-password" &&
          (input.credential !== undefined ||
            input.authorization.challenge.targetCredentialId !== undefined))
      )
        return undefined;
      if (
        input.expectedRevision.credentials.some(
          (expected) =>
            !input.authorization.evidence.revision.credentials.some(
              (actual) =>
                actual.credentialId === expected.credentialId &&
                actual.revision === expected.revision,
            ),
        )
      )
        return undefined;
      if (input.credential !== undefined) {
        const identifier = (yield* lockIdentifier(
          mapping,
          input.credential.identifier,
          configuration.locking,
        ))[0];

        if (
          identifier === undefined ||
          !mapping.identifier.isCurrent(identifier) ||
          !mapping.subjectId.equals(
            identifier[mapping.identifier.subjectId],
            locked.nativeSubjectId,
          ) ||
          identifier[mapping.identifier.bindingRevision] !==
            input.credential.identifierBindingRevision
        )
          return undefined;
      }

      const allExpected = [
        ...input.expectedRevision.credentials,
        ...input.authorization.evidence.revision.credentials,
      ];

      const expected = new Map(allExpected.map((item) => [item.credentialId, item]));

      const ac = authorityCredentialColumns(mapping);

      const credentialRows =
        expected.size === 0
          ? []
          : yield* selectRows(
              database
                .select()
                .from(mapping.authorityCredential.table)
                .where(
                  and(
                    eq(ac.subjectId, locked.nativeSubjectId),
                    inArray(ac.credentialId, [...expected.keys()]),
                  ),
                )
                .orderBy(ac.credentialId),
              configuration.locking,
            );

      if (credentialRows.length !== expected.size) return undefined;
      // Database collation need not match JavaScript locale ordering.
      for (const actual of credentialRows) {
        const wanted = expected.get(actual[mapping.authorityCredential.credentialId]);

        if (
          wanted === undefined ||
          actual[mapping.authorityCredential.revision] !== wanted.revision ||
          (mapping.authorityCredential.status !== undefined &&
            mapping.authorityCredential.isActiveStatus?.(
              actual[mapping.authorityCredential.status],
            ) !== true)
        )
          return undefined;
        expected.delete(wanted.credentialId);
      }
      if (expected.size !== 0) return undefined;
      if (input.credential !== undefined) {
        const identifier = (yield* lockIdentifier(mapping, input.credential.identifier, false))[0];

        const credential = (yield* readPasswordCredential(
          mapping,
          input.moduleId,
          locked.nativeSubjectId,
          configuration.locking,
        ))[0];

        if (identifier === undefined || credential === undefined) return undefined;

        const snapshot = yield* mapping.credential.decode({
          moduleId: input.moduleId,
          subject: row,
          identifier,
          credential,
        });

        if (!sameCredentialSnapshot(snapshot, input.credential)) return undefined;
      }
      const currentRequirement = yield* mapping.subject.decodeActionRequirement(row, action);
      const now = yield* nowMillis;

      if (
        !evidenceSatisfiedAt(input.authorization.evidence, input.authorization.requirement, now) ||
        !evidenceSatisfiedAt(input.authorization.evidence, currentRequirement, now)
      )
        return undefined;
      if (
        input.invalidation.existingSessions === "immediate" &&
        mapping.sessionInvalidation !== "same-authority-immediate"
      )
        return undefined;

      return { ...locked, now };
    },
  );

  const commandExists = Effect.fn("Drizzle.commandExists")(function* (
    mapping: Mapping,
    moduleId: string,
    commandId: string,
    locking: boolean,
  ) {
    const database = yield* CurrentPasswordSql;

    const c = commandColumns(mapping);

    return yield* selectRows(
      database
        .select()
        .from(mapping.command.table)
        .where(and(eq(c.moduleId, moduleId), eq(c.commandId, commandId)))
        .limit(1),
      locking,
    );
  });

  const insertCommand = Effect.fn("Drizzle.insertCommand")(function* (
    mapping: Mapping,
    input: PasswordMutationInput,
    action: PasswordAction,
    now: number,
  ) {
    const database = yield* CurrentPasswordSql;

    return yield* database.insert(mapping.command.table).values(
      mapping.command.encodeInsert({
        moduleId: input.moduleId,
        commandId: input.commandId,
        action,
        bindingDigest: input.authorization.challenge.bindingDigest,
        decision: "changed",
        retentionUntilMillis: now + mapping.commandRetentionMillis,
      }),
    );
  });

  const mutationPostconditions = Effect.fn("DrizzlePassword.mutationPostconditions")(function* (
    mapping: Mapping,
    input: PasswordMutationInput,
    nativeSubjectId: unknown,
    subject: any,
    authorityCredential: any,
    now: number,
  ) {
    if (
      subject === undefined ||
      !mapping.subject.isActiveStatus(subject[mapping.subject.status]) ||
      authorityCredential === undefined ||
      (mapping.authorityCredential.status !== undefined &&
        mapping.authorityCredential.isActiveStatus?.(
          authorityCredential[mapping.authorityCredential.status],
        ) !== true)
    )
      return false;
    if (input.credential !== undefined) {
      const identifier = (yield* lockIdentifier(mapping, input.credential.identifier, false))[0];

      if (
        identifier === undefined ||
        !mapping.identifier.isCurrent(identifier) ||
        !mapping.subjectId.equals(identifier[mapping.identifier.subjectId], nativeSubjectId) ||
        identifier[mapping.identifier.bindingRevision] !==
          input.credential.identifierBindingRevision
      )
        return false;

      const credential = (yield* readPasswordCredential(
        mapping,
        input.moduleId,
        nativeSubjectId,
        false,
      ))[0];

      if (credential === undefined) return false;

      const decoded = yield* mapping.credential.decode({
        moduleId: input.moduleId,
        subject,
        identifier,
        credential,
      });

      if (decoded.identifierVerifiedAtMillis !== input.credential.identifierVerifiedAtMillis)
        return false;
    }
    const rows = yield* commandExists(mapping, input.moduleId, input.commandId, false);
    const row = rows[0];

    return (
      rows.length === 1 &&
      row[mapping.command.action] === input.authorization.challenge.action &&
      row[mapping.command.bindingDigest] === input.authorization.challenge.bindingDigest &&
      row[mapping.command.decision] === "changed" &&
      (yield* mapping.decodeInstant(row[mapping.command.retentionUntil])) ===
        now + mapping.commandRetentionMillis
    );
  });

  const addPasswordIn = Effect.fn("DrizzlePassword.addPasswordIn")(function* (
    mapping: Mapping,
    configuration: PasswordSqlConfiguration,
    input: PasswordMutationInput,
    revisions: {
      readonly credentialId: string;
      readonly credentialRevision: SecurityRevision;
      readonly verifierVersion: SecurityRevision;
      readonly nextSecurityRevision: SecurityRevision;
    },
    commandNow?: number,
  ) {
    const database = yield* CurrentPasswordSql;

    const { credentialId, credentialRevision, verifierVersion, nextSecurityRevision } = revisions;

    const authority = yield* validateMutationAuthority(
      mapping,
      configuration,
      input,
      "add-password",
    );

    if (authority === undefined) return false;
    if ((yield* commandExists(mapping, input.moduleId, input.commandId, true)).length) return false;
    if (
      (yield* readPasswordCredential(mapping, input.moduleId, authority.nativeSubjectId, true))
        .length
    )
      return false;

    yield* database.insert(mapping.credential.table).values(
      mapping.credential.encodeInsert({
        moduleId: input.moduleId,
        subjectId: authority.nativeSubjectId,
        credentialId,
        credentialRevision,
        verifierVersion,
        replacement: input.replacement,
      }),
    );
    yield* database.insert(mapping.authorityCredential.table).values(
      mapping.authorityCredential.encodeInsert({
        subjectId: authority.nativeSubjectId,
        credentialId,
        revision: credentialRevision,
      }),
    );
    yield* database
      .update(mapping.subject.table)
      .set(updateValues([[mapping.subject.securityRevision, nextSecurityRevision]]))
      .where(
        and(
          eq(subjectColumns(mapping).id, authority.nativeSubjectId),
          eq(subjectColumns(mapping).securityRevision, input.expectedRevision.securityRevision),
        ),
      );
    yield* insertCommand(mapping, input, "add-password", commandNow ?? authority.now);

    const applied = checkMutationApplied(
      mapping,
      input,
      authority.nativeSubjectId,
      revisions,
      commandNow ?? authority.now,
    );

    if (!(yield* applied)) return yield* unavailable();
    yield* registerFinal(applied);

    return true;
  });

  const makeSqlPasswordPersistence = Effect.fn("makeSqlPasswordPersistence")(function* (
    mapping: Mapping,
    configuration: PasswordSqlConfiguration,
  ): Effect.fn.Return<
    PasswordPersistence["Service"],
    PasswordUnavailable,
    LifecycleHooks | CurrentPasswordSql | NativeDatabase
  > {
    const database = yield* CurrentPasswordSql;

    if (!configuration.coordinated)
      yield* (
        operations.validateStorage?.({
          ...mapping,
          proof: configuration.proof?.mapping,
        }) ?? Effect.void
      ).pipe(Effect.mapError(unavailable));
    const hooks = yield* LifecycleHooks;

    if (!validConstraints(mapping)) return yield* unavailable();
    const root = yield* NativeDatabase;

    const attempts = yield* makePasswordAttempts(
      yield* sqlMapping(() => nativeTables(root.$client.withoutTransforms(), root)).pipe(
        translateFailure,
      ),
      mapping,
      configuration,
    );

    return PasswordPersistence.of({
      ...attempts,
      readForSubject: (input) =>
        safeRead(
          database,
          configuration,
          Effect.gen(function* () {
            const transaction = yield* CurrentPasswordSql;

            const locked = yield* lockSubject(mapping, input.subjectId, false);

            if (
              locked.row === undefined ||
              !mapping.subject.isActiveStatus(locked.row[mapping.subject.status])
            )
              return Option.none();

            const credential = (yield* readPasswordCredential(
              mapping,
              input.moduleId,
              locked.nativeSubjectId,
              false,
            ))[0];

            if (credential === undefined) return Option.none();
            const ic = identifierColumns(mapping);

            const identifiers = yield* transaction
              .select()
              .from(mapping.identifier.table)
              .where(eq(ic.subjectId, locked.nativeSubjectId));

            const identifier = identifiers.find((row: any) => mapping.identifier.isCurrent(row));

            if (identifier === undefined) return Option.none();

            const snapshot = yield* mapping.credential
              .decode({
                moduleId: input.moduleId,
                subject: locked.row,
                identifier,
                credential,
              })
              .pipe(Effect.flatMap(snapshotPasswordCredential));

            return Option.some(snapshot);
          }),
        ).pipe(
          Effect.provideService(CurrentPasswordSql, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
      recoveryTarget: (input) =>
        safeRead(
          database,
          configuration,
          Effect.gen(function* () {
            const resolved = yield* resolveCredential(
              mapping,
              input.moduleId,
              input.identifier,
              undefined,
              false,
            );

            return resolved?.snapshot === undefined ||
              resolved.snapshot.identifierVerifiedAtMillis === undefined
              ? Option.none()
              : Option.some(resolved.snapshot);
          }),
        ).pipe(
          Effect.provideService(CurrentPasswordSql, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
      addIfAbsent: (uncaptured, prepare) =>
        Effect.gen(function* () {
          const input = yield* snapshotMutationInput(uncaptured);

          const credentialId = yield* allocate(
            configuration.mode,
            mapping.allocateCredentialId,
            mapping.allocateCredentialIdSync,
          );

          const credentialRevision = yield* allocate(
            configuration.mode,
            mapping.allocateRevision,
            mapping.allocateRevisionSync,
          );

          const verifierVersion = yield* allocate(
            configuration.mode,
            mapping.allocateRevision,
            mapping.allocateRevisionSync,
          );

          const nextSecurityRevision = yield* allocateNextSecurityRevision(
            mapping,
            configuration.mode,
            input.expectedRevision.securityRevision,
          );

          if (nextSecurityRevision === input.expectedRevision.securityRevision)
            return yield* unavailable();

          return yield* owned(
            database,
            mapping,
            configuration,
            Effect.gen(function* () {
              const journal = yield* CurrentCommitJournal;

              const changed = yield* addPasswordIn(mapping, configuration, input, {
                credentialId,
                credentialRevision,
                verifierVersion,
                nextSecurityRevision,
              });

              return prepare(changed ? "changed" : "rejected", journal);
            }),
          );
        }).pipe(
          Effect.provideService(CurrentPasswordSql, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
      replaceIfCurrent: (uncaptured, prepare) =>
        Effect.gen(function* () {
          const input = yield* snapshotMutationInput(uncaptured);

          const credentialRevision = yield* allocate(
            configuration.mode,
            mapping.allocateRevision,
            mapping.allocateRevisionSync,
          );

          const verifierVersion = yield* allocate(
            configuration.mode,
            mapping.allocateRevision,
            mapping.allocateRevisionSync,
          );

          const nextSecurityRevision = yield* allocateNextSecurityRevision(
            mapping,
            configuration.mode,
            input.expectedRevision.securityRevision,
          );

          if (
            nextSecurityRevision === input.expectedRevision.securityRevision ||
            (input.credential !== undefined &&
              credentialRevision === input.credential.credentialRevision)
          )
            return yield* unavailable();

          return yield* owned(
            database,
            mapping,
            configuration,
            Effect.gen(function* () {
              return yield* replaceIn(
                mapping,
                configuration,
                input,
                "change-password",
                { credentialRevision, verifierVersion, nextSecurityRevision },
                prepare,
              );
            }),
          );
        }).pipe(
          Effect.provideService(CurrentPasswordSql, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
      checkReset: (input) =>
        (configuration.proof === undefined
          ? Effect.fail(unavailable())
          : Effect.gen(function* () {
              if (
                input.moduleId.length <= "/reset".length ||
                !input.moduleId.endsWith("/reset") ||
                input.purpose !== "password-reset" ||
                input.binding._tag !== "Subject"
              )
                return false;
              const binding = input.binding;
              const passwordModuleId = input.moduleId.slice(0, -"/reset".length);

              const current = yield* safeRead(
                database,
                configuration,
                Effect.gen(function* () {
                  const resolved = yield* resolveCredential(
                    mapping,
                    passwordModuleId,
                    binding.identifier,
                    binding.revision.subjectId,
                    false,
                  );

                  return (
                    resolved?.snapshot !== undefined &&
                    resolved.snapshot.revision.securityRevision ===
                      binding.revision.securityRevision &&
                    binding.revision.credentials.every((item) =>
                      resolved.snapshot!.revision.credentials.some(
                        (actual) =>
                          actual.credentialId === item.credentialId &&
                          actual.revision === item.revision,
                      ),
                    )
                  );
                }),
              );

              return current ? yield* probeProofCompletion(configuration, input) : false;
            })
        ).pipe(
          Effect.provideService(CurrentPasswordSql, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
      resetWithProof: (uncaptured, prepare) =>
        (configuration.proof === undefined
          ? Effect.fail(unavailable())
          : Effect.gen(function* () {
              const input = Object.freeze({
                ...(yield* snapshotMutationInput(uncaptured)),
                completion: uncaptured.completion,
              });

              const credentialRevision = yield* allocate(
                configuration.mode,
                mapping.allocateRevision,
                mapping.allocateRevisionSync,
              );

              const verifierVersion = yield* allocate(
                configuration.mode,
                mapping.allocateRevision,
                mapping.allocateRevisionSync,
              );

              const nextSecurityRevision = yield* allocateNextSecurityRevision(
                mapping,
                configuration.mode,
                input.expectedRevision.securityRevision,
              );

              if (
                nextSecurityRevision === input.expectedRevision.securityRevision ||
                (input.credential !== undefined &&
                  credentialRevision === input.credential.credentialRevision)
              )
                return yield* unavailable();

              return yield* owned(
                database,
                mapping,
                configuration,
                Effect.gen(function* () {
                  const journal = yield* CurrentCommitJournal;

                  if (!proofCompletionMatchesPassword(input)) return prepare("rejected", journal);

                  const authority = yield* validateMutationAuthority(
                    mapping,
                    configuration,
                    input,
                    "reset-password",
                  );

                  if (authority === undefined) return prepare("rejected", journal);
                  if ((yield* commandExists(mapping, input.moduleId, input.commandId, true)).length)
                    return prepare("rejected", journal);

                  const current = yield* currentExpectedCredential(
                    mapping,
                    input,
                    authority.nativeSubjectId,
                  );

                  if (!current) return prepare("rejected", journal);
                  let passwordReceipt: PreparedCommit<any> | undefined;

                  yield* completeProofPlanIn(
                    configuration.proof!.mapping,
                    configuration.proof!.configuration,
                    input.completion,
                    Effect.gen(function* () {
                      const revisions = {
                        credentialRevision,
                        verifierVersion,
                        nextSecurityRevision,
                      };

                      const applied = yield* writeReplacement(
                        mapping,
                        input,
                        authority.nativeSubjectId,
                        revisions,
                        authority.now,
                      );

                      if (applied)
                        yield* registerReplacement(
                          mapping,
                          input,
                          authority.nativeSubjectId,
                          revisions,
                          authority.now,
                        );

                      return applied;
                    }),
                    (decision) => {
                      passwordReceipt = prepare(
                        decision === "completed" ? "changed" : "rejected",
                        journal,
                      );

                      return decision;
                    },
                  );

                  return passwordReceipt ?? prepare("rejected", journal);
                }),
              );
            })
        ).pipe(
          Effect.provideService(CurrentPasswordSql, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
      cleanupAttempts: (input, prepare) =>
        owned(
          database,
          mapping,
          configuration,
          Effect.gen(function* () {
            const transaction = yield* CurrentPasswordSql;
            const journal = yield* CurrentCommitJournal;

            const now = yield* nowMillis;
            const nativeNow = mapping.encodeInstant(now);
            const a = attemptColumns(mapping);

            const attempts = yield* selectRows(
              transaction
                .select({ attemptId: a.attemptId })
                .from(mapping.attempt.table)
                .where(and(eq(a.moduleId, input.moduleId), lte(a.retentionUntil, nativeNow)))
                .limit(input.limit + 1),
              false,
            );

            const hasMore = attempts.length > input.limit;
            const attemptCandidates = attempts.slice(0, input.limit);
            const selectedAttempts: typeof attemptCandidates = [];

            for (const candidate of attemptCandidates) {
              const locked = yield* selectRows(
                transaction
                  .select({ attemptId: a.attemptId })
                  .from(mapping.attempt.table)
                  .where(
                    and(
                      eq(a.moduleId, input.moduleId),
                      eq(a.attemptId, candidate.attemptId),
                      lte(a.retentionUntil, nativeNow),
                    ),
                  )
                  .limit(1),
                configuration.locking,
              );

              if (locked[0] !== undefined) selectedAttempts.push(locked[0] as any);
            }

            const prepared = prepare(
              {
                removed: selectedAttempts.length,
                hasMore,
              },
              journal,
            );

            if (selectedAttempts.length > 0)
              yield* transaction.delete(mapping.attempt.table).where(
                and(
                  eq(a.moduleId, input.moduleId),
                  inArray(
                    a.attemptId,
                    selectedAttempts.map((row: any) => row.attemptId),
                  ),
                  lte(a.retentionUntil, nativeNow),
                ),
              );

            return prepared;
          }),
        ).pipe(
          Effect.provideService(CurrentPasswordSql, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
    });
  });

  const currentExpectedCredential = Effect.fn("DrizzlePassword.currentExpectedCredential")(
    function* (mapping: Mapping, input: PasswordMutationInput, nativeSubjectId: unknown) {
      if (input.credential === undefined) return false;

      const row = (yield* readPasswordCredential(
        mapping,
        input.moduleId,
        nativeSubjectId,
        true,
      ))[0];

      if (row === undefined) return false;

      return (
        row[mapping.credential.credentialId] === input.credential.credentialId &&
        row[mapping.credential.credentialRevision] === input.credential.credentialRevision &&
        row[mapping.credential.verifierVersion] === input.credential.verifierVersion &&
        row[mapping.credential.verifier] === Redacted.value(input.credential.verifier) &&
        row[mapping.credential.normalization] === input.credential.normalization &&
        input.authorization.challenge.targetCredentialId === input.credential.credentialId
      );
    },
  );

  const checkMutationApplied = Effect.fn("DrizzlePassword.checkMutationApplied")(function* (
    mapping: Mapping,
    input: PasswordMutationInput,
    nativeSubjectId: unknown,
    revisions: {
      readonly credentialId: string;
      readonly credentialRevision: SecurityRevision;
      readonly verifierVersion: SecurityRevision;
      readonly nextSecurityRevision: SecurityRevision;
    },
    now: number,
  ) {
    const database = yield* CurrentPasswordSql;

    const c = credentialColumns(mapping),
      s = subjectColumns(mapping);

    const credential = (yield* database
      .select()
      .from(mapping.credential.table)
      .where(
        and(
          eq(c.moduleId, input.moduleId),
          eq(c.subjectId, nativeSubjectId),
          eq(c.credentialId, revisions.credentialId),
          eq(c.credentialRevision, revisions.credentialRevision),
          eq(c.verifierVersion, revisions.verifierVersion),
          eq(c.verifier, Redacted.value(input.replacement.verifier)),
          eq(c.normalization, input.replacement.normalization),
        ),
      )
      .limit(1))[0];

    const subject = (yield* database
      .select()
      .from(mapping.subject.table)
      .where(and(eq(s.id, nativeSubjectId), eq(s.securityRevision, revisions.nextSecurityRevision)))
      .limit(1))[0];

    const authorityCredential = (yield* database
      .select()
      .from(mapping.authorityCredential.table)
      .where(
        and(
          eq(authorityCredentialColumns(mapping).subjectId, nativeSubjectId),
          eq(authorityCredentialColumns(mapping).credentialId, revisions.credentialId),
          eq(authorityCredentialColumns(mapping).revision, revisions.credentialRevision),
        ),
      )
      .limit(1))[0];

    // SQL equality follows column collation; compare the persisted values exactly.
    return (
      credential !== undefined &&
      credential[mapping.credential.credentialId] === revisions.credentialId &&
      credential[mapping.credential.credentialRevision] === revisions.credentialRevision &&
      credential[mapping.credential.verifierVersion] === revisions.verifierVersion &&
      credential[mapping.credential.verifier] === Redacted.value(input.replacement.verifier) &&
      credential[mapping.credential.normalization] === input.replacement.normalization &&
      (yield* mutationPostconditions(
        mapping,
        input,
        nativeSubjectId,
        subject,
        authorityCredential,
        now,
      ))
    );
  });

  const writeReplacement = Effect.fn("DrizzlePassword.writeReplacement")(function* (
    mapping: Mapping,
    input: PasswordMutationInput,
    nativeSubjectId: unknown,
    revisions: {
      readonly credentialRevision: SecurityRevision;
      readonly verifierVersion: SecurityRevision;
      readonly nextSecurityRevision: SecurityRevision;
    },
    now: number,
  ) {
    const database = yield* CurrentPasswordSql;

    const c = credentialColumns(mapping);
    const s = subjectColumns(mapping);

    yield* database
      .update(mapping.credential.table)
      .set(
        mapping.credential.encodeReplacement({
          replacement: input.replacement,
          credentialRevision: revisions.credentialRevision,
          verifierVersion: revisions.verifierVersion,
        }),
      )
      .where(
        and(
          eq(c.moduleId, input.moduleId),
          eq(c.subjectId, nativeSubjectId),
          eq(c.credentialId, input.credential!.credentialId),
          eq(c.credentialRevision, input.credential!.credentialRevision),
          eq(c.verifierVersion, input.credential!.verifierVersion),
          eq(c.verifier, Redacted.value(input.credential!.verifier)),
          eq(c.normalization, input.credential!.normalization),
        ),
      );
    yield* database
      .update(mapping.subject.table)
      .set(updateValues([[mapping.subject.securityRevision, revisions.nextSecurityRevision]]))
      .where(
        and(
          eq(s.id, nativeSubjectId),
          eq(s.securityRevision, input.expectedRevision.securityRevision),
        ),
      );
    yield* database
      .update(mapping.authorityCredential.table)
      .set(mapping.authorityCredential.encodeRevision(revisions.credentialRevision))
      .where(
        and(
          eq(authorityCredentialColumns(mapping).subjectId, nativeSubjectId),
          eq(authorityCredentialColumns(mapping).credentialId, input.credential!.credentialId),
          eq(authorityCredentialColumns(mapping).revision, input.credential!.credentialRevision),
        ),
      );
    yield* insertCommand(mapping, input, input.authorization.challenge.action, now);

    return yield* checkMutationApplied(
      mapping,
      input,
      nativeSubjectId,
      {
        ...revisions,
        credentialId: input.credential!.credentialId,
      },
      now,
    );
  });

  const registerReplacement = (
    mapping: Mapping,
    input: PasswordMutationInput,
    nativeSubjectId: unknown,
    revisions: {
      readonly credentialRevision: SecurityRevision;
      readonly verifierVersion: SecurityRevision;
      readonly nextSecurityRevision: SecurityRevision;
    },
    now: number,
  ) =>
    registerFinal(
      checkMutationApplied(
        mapping,
        input,
        nativeSubjectId,
        { ...revisions, credentialId: input.credential!.credentialId },
        now,
      ),
    );

  const replaceIn = Effect.fn("Drizzle.replaceIn")(function* <A>(
    mapping: Mapping,
    configuration: PasswordSqlConfiguration,
    input: PasswordMutationInput,
    action: PasswordAction,
    revisions: {
      readonly credentialRevision: SecurityRevision;
      readonly verifierVersion: SecurityRevision;
      readonly nextSecurityRevision: SecurityRevision;
    },
    prepare: (value: PasswordMutationDecision, journal: CommitJournal) => PreparedCommit<A>,
  ) {
    const journal = yield* CurrentCommitJournal;

    const authority = yield* validateMutationAuthority(mapping, configuration, input, action);

    if (authority === undefined) return prepare("rejected", journal);
    if ((yield* commandExists(mapping, input.moduleId, input.commandId, true)).length)
      return prepare("rejected", journal);
    if (!(yield* currentExpectedCredential(mapping, input, authority.nativeSubjectId)))
      return prepare("rejected", journal);
    const prepared = prepare("changed", journal);

    if (
      !(yield* writeReplacement(
        mapping,
        input,
        authority.nativeSubjectId,
        revisions,
        authority.now,
      ))
    )
      return yield* unavailable();
    yield* registerReplacement(mapping, input, authority.nativeSubjectId, revisions, authority.now);

    return prepared;
  });

  /** Internal bound-owner primitives; deliberately not re-exported by driver modules. */
  const passwordSqlKernel = {
    allocate,
    allocateNextSecurityRevision,
    owned,
    safeRead,
    snapshotMutationInput,
    lockSubject,
    lockIdentifier,
    readPasswordCredential,
    resolveCredential,
    validateMutationAuthority,
    currentExpectedCredential,
    commandExists,
    addPasswordIn,
    checkMutationApplied,
    writeReplacement,
    evidenceSatisfiedAt,
    sameCredentialSnapshot,
    subjectColumns,
    identifierColumns,
    credentialColumns,
    authorityCredentialColumns,
    proofCompletionMatchesPassword,
  };

  return { makeSqlPasswordPersistence, passwordSqlKernel };
};
