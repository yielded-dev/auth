/* oxlint-disable no-explicit-any -- D1 plans bridge consumer-owned Drizzle rows and SQL statements. */
import type { D1Client } from "@effect/sql-d1/D1Client";
import {
  NativeDatabase,
  requireStandalone,
  samePasswordCredentialSnapshot as sameSnapshot,
} from "@yielded/auth-persistence/Adapter";
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
  EncodedPasswordHash,
  PasswordUnavailable,
  PasswordPersistence,
  type PasswordMutationInput,
  type PreparePasswordCommit,
  snapshotPasswordCredential,
  snapshotPasswordRequirement,
  snapshotPasswordRevision,
  type PasswordAction,
  type PasswordMutationDecision,
} from "@yielded/auth/Password";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import {
  type ProofCompletionPlan,
  type ProofCompletionDecision,
  type ProofCompletionInput,
  ProofUnavailable,
} from "@yielded/auth/Proofs";
import {
  snapshotAuthenticationEvidence,
  AuthenticationEvidence,
  AuthenticationRequirement,
  type SecurityRevision,
} from "@yielded/auth/Sessions";
import {
  and,
  eq,
  getTableColumns,
  inArray,
  sql,
  type AnyRelations,
  type SQL,
  type Table,
} from "drizzle-orm";
import type { EffectSQLiteD1Database } from "drizzle-orm/effect-d1";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Cause, DateTime, Effect, Option, Predicate, Redacted, Schema, Context } from "effect";
import type { Statement } from "effect/sql/Statement";

import { Database as DatabaseService } from "./d1-database";
import { balancedD1And } from "./d1-generated-statement";
import { CurrentD1PlanningDatabase, makeD1Owner } from "./d1-planning";
import { compileD1ProofCompletionPlan, type D1ProtectedProofMutation } from "./d1-proofs";
import { D1BatchStatements } from "./D1BatchStatements";
import { column, isMappedConstraintConflict, PersistenceMappingError, updateValues } from "./model";
import { nativeDatabase } from "./native-database";
import {
  type AnyPasswordRegistrationMapping,
  type D1PasswordPersistenceMapping,
  type PasswordRegistrationMapping,
  requiredPasswordConstraints,
  requiredPasswordRegistrationConstraints,
} from "./password-model";
import type { PasswordRegistrationAuthority } from "./password-registration";
import type { D1ProofPersistenceMapping } from "./proof-model";
import { validateDrizzleStorage } from "./storage-validation";
import type { SuppliedService } from "./SuppliedService";

type PlanPrepare<Method extends (...args: any[]) => any, A> = (
  value: Parameters<Parameters<Method>[1]>[0],
  journal: CommitJournal,
) => PreparedCommit<A>;

type Database = EffectSQLiteD1Database<AnyRelations> & { readonly $client: D1Client };
type Mapping = D1PasswordPersistenceMapping<Table, Table, Table, Table, Table, unknown>;
type RegistrationMapping<Registration> = AnyPasswordRegistrationMapping<Registration>;

interface Planned<A> {
  readonly receipt: A;
  readonly statements: ReadonlyArray<Statement<any>>;
  /** Final-state guards without `changes()`, repeated after coordinated statements. */
  readonly postconditions?: ReadonlyArray<Statement<any>>;
  readonly retryable?: (cause: unknown) => boolean;
  readonly journalGuard?: PreparedCommit<void>;
}

const unavailable = () => PasswordUnavailable.make({});

const everyFailureMatches = (
  cause: Cause.Cause<unknown>,
  classify: ((cause: unknown) => boolean) | undefined,
): boolean =>
  classify !== undefined &&
  cause.reasons.length > 0 &&
  cause.reasons.every((reason) => Cause.isFailReason(reason) && classify(Cause.fail(reason.error)));

const validConstraints = (mapping: Mapping) =>
  Object.entries(requiredPasswordConstraints).every(
    ([key, value]) =>
      mapping.constraints[key as keyof typeof requiredPasswordConstraints] === value,
  );

const validRegistrationConstraints = <Registration>(mapping: RegistrationMapping<Registration>) =>
  Object.entries(requiredPasswordRegistrationConstraints).every(
    ([key, value]) =>
      mapping.constraints[key as keyof typeof requiredPasswordRegistrationConstraints] === value,
  );

const containsFailure = (failure: unknown, predicate: (value: unknown) => boolean): boolean => {
  const seen = new Set<unknown>();
  const pending: Array<unknown> = [failure];

  for (let inspected = 0; inspected < 32 && pending.length > 0; inspected++) {
    const current = pending.shift();

    if (current === undefined || current === null || seen.has(current)) continue;
    seen.add(current);
    if (predicate(current)) return true;
    if (Cause.isCause(current)) {
      for (const reason of current.reasons) {
        if (Cause.isFailReason(reason)) pending.push(reason.error);
        else if (Cause.isDieReason(reason)) pending.push(reason.defect);
      }
      continue;
    }
    if (typeof current !== "object") continue;

    const wrapped = current as {
      readonly cause?: unknown;
      readonly reason?: unknown;
      readonly message?: unknown;
    };

    if (wrapped.cause !== undefined) pending.push(wrapped.cause);
    if (wrapped.reason !== undefined) pending.push(wrapped.reason);
    if (wrapped.message !== undefined) pending.push(wrapped.message);
  }

  return false;
};

// Match only workerd's native SQLite diagnostic. A wrapper that merely echoes
// the bound marker is not evidence that the guard ran and rolled back the batch.
const isGuardFailure = (cause: unknown, marker: string) => {
  const path = `$[${marker.replaceAll("'", "''")}]`;
  const native = `bad JSON path: '${path}': SQLITE_ERROR`;

  return containsFailure(cause, (value) => value === native || value === `D1_ERROR: ${native}`);
};

const statement = Effect.fn(function* (query: {
  readonly toSQL: () => { readonly sql: string; readonly params: unknown[] };
}) {
  const database = yield* CurrentD1PlanningDatabase;
  const rendered = query.toSQL();

  return database.$client.unsafe(rendered.sql, rendered.params);
});

const assertion = Effect.fn(function* (condition: SQL, marker: string) {
  const database = yield* CurrentD1PlanningDatabase;

  return yield* statement(
    database
      .select({
        ok: sql`case when ${condition} then 1 else json_extract('[]', ${`$[${marker}]`}) end`.as(
          "ok",
        ),
      })
      .from(sql`(select 1)`),
  );
});

const readEngineNowMillis = Effect.fn("Drizzle.readEngineNowMillis")(function* (mapping: Mapping) {
  const database = yield* CurrentD1PlanningDatabase;

  return yield* database
    .select({ value: mapping.d1.engineNowMillis.as("engine_now_millis") })
    .from(sql`(select 1)`)
    .pipe(
      Effect.flatMap((rows) => {
        const value = Number(rows[0]?.value);

        return Number.isFinite(value) ? Effect.succeed(value) : Effect.fail(unavailable());
      }),
    );
});

const allocate = <A>(
  asyncValue: Effect.Effect<A, PersistenceMappingError> | undefined,
  syncValue: (() => A) | undefined,
) =>
  asyncValue !== undefined
    ? asyncValue
    : syncValue === undefined
      ? Effect.fail(unavailable())
      : Effect.try({
          try: syncValue,
          catch: (cause) => new PersistenceMappingError({ operation: "mapping", cause }),
        });

const allocateNextSecurityRevision = (mapping: Mapping, current: SecurityRevision) =>
  allocate(
    mapping.subject.nextSecurityRevision?.(current) ?? mapping.allocateRevision,
    mapping.subject.nextSecurityRevisionSync === undefined
      ? mapping.allocateRevisionSync
      : () => mapping.subject.nextSecurityRevisionSync!(current),
  );

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

const authorityColumns = (mapping: Mapping) => ({
  subjectId: column(mapping.authorityCredential.table, mapping.authorityCredential.subjectId),
  credentialId: column(mapping.authorityCredential.table, mapping.authorityCredential.credentialId),
  revision: column(mapping.authorityCredential.table, mapping.authorityCredential.revision),
  status:
    mapping.authorityCredential.status === undefined
      ? undefined
      : column(mapping.authorityCredential.table, mapping.authorityCredential.status),
});

const commandColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.command.table, mapping.command.moduleId),
  commandId: column(mapping.command.table, mapping.command.commandId),
  action: column(mapping.command.table, mapping.command.action),
  bindingDigest: column(mapping.command.table, mapping.command.bindingDigest),
  decision: column(mapping.command.table, mapping.command.decision),
  retentionUntil: column(mapping.command.table, mapping.command.retentionUntil),
});

const readIdentifier = Effect.fn("Drizzle.readIdentifier")(function* (
  mapping: Mapping,
  identifier: LoginIdentifier,
) {
  const database = yield* CurrentD1PlanningDatabase;

  const c = identifierColumns(mapping);

  return yield* database
    .select()
    .from(mapping.identifier.table)
    .where(and(eq(c.namespace, identifier.namespace), eq(c.value, identifier.value)))
    .limit(1);
});

const readSubjectNative = Effect.fn("Drizzle.readSubjectNative")(function* (
  mapping: Mapping,
  nativeSubjectId: unknown,
) {
  const database = yield* CurrentD1PlanningDatabase;

  return yield* database
    .select()
    .from(mapping.subject.table)
    .where(eq(subjectColumns(mapping).id, nativeSubjectId))
    .limit(1);
});

const readCredentialNative = Effect.fn("Drizzle.readCredentialNative")(function* (
  mapping: Mapping,
  moduleId: string,
  nativeSubjectId: unknown,
) {
  const database = yield* CurrentD1PlanningDatabase;

  const c = credentialColumns(mapping);

  return yield* database
    .select()
    .from(mapping.credential.table)
    .where(and(eq(c.moduleId, moduleId), eq(c.subjectId, nativeSubjectId)))
    .limit(1);
});

const resolveCredential = Effect.fn("DrizzleD1Password.resolveCredential")(function* (
  mapping: Mapping,
  moduleId: string,
  identifier: LoginIdentifier,
  requestedSubjectId?: string,
) {
  const identifierRow = (yield* readIdentifier(mapping, identifier))[0];

  if (identifierRow === undefined || !mapping.identifier.isCurrent(identifierRow)) return undefined;
  const nativeSubjectId = identifierRow[mapping.identifier.subjectId];
  const subject = (yield* readSubjectNative(mapping, nativeSubjectId))[0];

  if (subject === undefined || !mapping.subject.isActiveStatus(subject[mapping.subject.status]))
    return undefined;
  const subjectId = yield* mapping.subjectId.toSubject(nativeSubjectId);

  if (requestedSubjectId !== undefined && subjectId !== requestedSubjectId) return undefined;
  const credential = (yield* readCredentialNative(mapping, moduleId, nativeSubjectId))[0];

  if (credential === undefined) return { nativeSubjectId, subject, identifier: identifierRow };

  const snapshot = yield* mapping.credential
    .decode({ moduleId, subject, identifier: identifierRow, credential })
    .pipe(Effect.flatMap(snapshotPasswordCredential));

  return { nativeSubjectId, subject, identifier: identifierRow, credential, snapshot };
});

const evidenceProofsJson = Schema.encodeSync(
  Schema.fromJsonString(AuthenticationEvidence.fields.proofs),
);

const alternativesJson = Schema.encodeSync(
  Schema.fromJsonString(AuthenticationRequirement.fields.alternatives),
);

const assuranceCondition = (
  mapping: Mapping,
  evidence: PasswordMutationInput["authorization"]["evidence"],
  requirement: PasswordMutationInput["authorization"]["requirement"],
) => {
  const proofs = evidenceProofsJson(evidence.proofs);
  const fresh = sql`json_extract(proof.value, '$.verifiedAt') <= ${mapping.d1.engineNowMillis} and ${mapping.d1.engineNowMillis} - json_extract(proof.value, '$.verifiedAt') < ${requirement.maximumAgeMillis}`;

  return sql`exists(
    select 1 from json_each(${alternativesJson(requirement.alternatives)}) as alternative
    where not exists(select 1 from json_each(${proofs}) as proof where json_extract(proof.value, '$.verifiedAt') > ${mapping.d1.engineNowMillis})
    and not exists(select 1 from json_each(alternative.value, '$.factors') as factor where not exists(select 1 from json_each(${proofs}) as proof, json_each(proof.value, '$.factors') as held where ${fresh} and held.value = factor.value))
    and (select count(distinct json_extract(proof.value, '$.credentialId')) from json_each(${proofs}) as proof where ${fresh}) >= json_extract(alternative.value, '$.minimumCredentials')
    and exists(select 1 from json_each(${proofs}) as proof where ${fresh} and (json_extract(alternative.value, '$.userVerified') = 0 or json_extract(proof.value, '$.userVerified') = 1) and (json_extract(alternative.value, '$.phishingResistant') = 0 or json_extract(proof.value, '$.phishingResistant') = 1))
  )`;
};

const sameIdentifier = (left: LoginIdentifier, right: LoginIdentifier) =>
  left.namespace === right.namespace && left.value === right.value;

const evidenceSatisfiedAt = (
  evidence: PasswordMutationInput["authorization"]["evidence"],
  requirement: PasswordMutationInput["authorization"]["requirement"],
  now: number,
) => {
  if (evidence.proofs.length > 64 || evidence.revision.credentials.length > 64) return false;
  const revisions = new Map<string, string>();

  for (const revision of evidence.revision.credentials) {
    if (revisions.has(revision.credentialId)) return false;
    revisions.set(revision.credentialId, revision.revision);
  }
  if (evidence.proofs.some((proof) => !revisions.has(proof.credentialId))) return false;
  if (evidence.proofs.some((proof) => now < DateTime.toEpochMillis(proof.verifiedAt))) return false;

  const fresh = evidence.proofs.filter(
    (proof) => now - DateTime.toEpochMillis(proof.verifiedAt) < requirement.maximumAgeMillis,
  );

  const factors = new Set(fresh.flatMap((proof) => proof.factors));
  const credentials = new Set(fresh.map((proof) => proof.credentialId));

  return requirement.alternatives.some(
    (alternative) =>
      alternative.factors.every((factor) => factors.has(factor)) &&
      credentials.size >= alternative.minimumCredentials &&
      fresh.some(
        (proof) =>
          (!alternative.userVerified || proof.userVerified) &&
          (!alternative.phishingResistant || proof.phishingResistant),
      ),
  );
};

const snapshotMutationInput = Effect.fn("DrizzleD1Password.snapshotMutationInput")(function* (
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

const completionMatchesPassword = (
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

const probeProofCompletion = Effect.fn("DrizzleD1.probeProofCompletion")(function* (
  mapping: D1ProofPersistenceMapping<any, any, any, any, any, any, any, any, any, any, any, any>,
  input: ProofCompletionInput,
) {
  const database = yield* CurrentD1PlanningDatabase;

  const plan: ProofCompletionPlan = {
    input,
    prepare: (decision, journal, project) => journal.prepare(project(decision)),
  };

  const marker = `effect-auth-proof-guard:protected:${input.continuationId}`;

  const once = coordinateCommit(
    () =>
      Effect.gen(function* () {
        const compiled = yield* compileD1ProofCompletionPlan(
          mapping,
          plan,
          { statements: [], appliedCondition: sql`false` },
          () => false,
        );

        if (compiled.statements.length === 0) return false;
        yield* database.$client.batch(compiled.statements);

        return false;
      }),
    { mode: "batch" },
  );

  return yield* once.pipe(
    Effect.as(false),
    Effect.catchCause((cause) =>
      isGuardFailure(cause, marker) ? Effect.succeed(true) : Effect.failCause(cause),
    ),
  );
});

const identifierCurrentCondition = (
  mapping: Mapping,
  input: PasswordMutationInput,
  nativeSubjectId: unknown,
  nativeVerifiedAt: unknown,
) => {
  if (input.credential === undefined) return sql`true`;

  const ic = identifierColumns(mapping),
    snapshot = input.credential;

  return and(
    mapping.identifier.d1CurrentCondition({ identifier: snapshot.identifier, nativeSubjectId }),
    sql`exists(select 1 from ${mapping.identifier.table} where ${ic.namespace} = ${sql.param(snapshot.identifier.namespace, ic.namespace)} and ${ic.value} = ${sql.param(snapshot.identifier.value, ic.value)} and ${ic.subjectId} = ${sql.param(nativeSubjectId, ic.subjectId)} and ${ic.bindingRevision} = ${sql.param(snapshot.identifierBindingRevision, ic.bindingRevision)} and ${Predicate.isNullish(nativeVerifiedAt) ? sql`${ic.verifiedAt} is null` : sql`${ic.verifiedAt} = ${sql.param(nativeVerifiedAt, ic.verifiedAt)}`})`,
  )!;
};

const readAuthority = Effect.fn("DrizzleD1Password.readAuthority")(function* (
  mapping: Mapping,
  input: PasswordMutationInput,
  action: PasswordAction,
) {
  const database = yield* CurrentD1PlanningDatabase;

  if (
    input.authorization.evidence.proofs.length > 64 ||
    input.authorization.evidence.revision.credentials.length > 64
  )
    return undefined;

  const revisionIds = new Set(
    input.authorization.evidence.revision.credentials.map((item) => item.credentialId),
  );

  if (
    revisionIds.size !== input.authorization.evidence.revision.credentials.length ||
    input.authorization.evidence.proofs.some((proof) => !revisionIds.has(proof.credentialId))
  )
    return undefined;
  const nativeSubjectId = yield* mapping.subjectId.toNative(input.expectedRevision.subjectId);
  const subject = (yield* readSubjectNative(mapping, nativeSubjectId))[0];

  if (
    subject === undefined ||
    !mapping.subject.isActiveStatus(subject[mapping.subject.status]) ||
    subject[mapping.subject.securityRevision] !== input.expectedRevision.securityRevision ||
    input.authorization.challenge.moduleId !== input.moduleId ||
    input.authorization.challenge.action !== action ||
    input.authorization.challenge.commandId !== input.commandId ||
    input.authorization.challenge.revision.subjectId !== input.expectedRevision.subjectId ||
    input.authorization.challenge.revision.securityRevision !==
      input.expectedRevision.securityRevision ||
    input.authorization.evidence.revision.subjectId !== input.expectedRevision.subjectId ||
    input.authorization.evidence.revision.securityRevision !==
      input.expectedRevision.securityRevision ||
    (input.authorization.evidence.flowId as string) !== (input.commandId as string) ||
    input.authorization.evidence.bindingDigest !== input.authorization.challenge.bindingDigest ||
    (action === "add-password" &&
      (input.credential !== undefined ||
        input.authorization.challenge.targetCredentialId !== undefined)) ||
    input.expectedRevision.credentials.some(
      (expected) =>
        !input.authorization.evidence.revision.credentials.some(
          (actual) =>
            actual.credentialId === expected.credentialId && actual.revision === expected.revision,
        ),
    )
  )
    return undefined;
  let identifierCondition: SQL = sql`true`;

  if (input.credential !== undefined) {
    const identifier = (yield* readIdentifier(mapping, input.credential.identifier))[0];

    if (
      identifier === undefined ||
      input.authorization.challenge.targetCredentialId !== input.credential.credentialId ||
      !mapping.identifier.isCurrent(identifier) ||
      !mapping.subjectId.equals(identifier[mapping.identifier.subjectId], nativeSubjectId) ||
      identifier[mapping.identifier.bindingRevision] !== input.credential.identifierBindingRevision
    )
      return undefined;
    const credential = (yield* readCredentialNative(mapping, input.moduleId, nativeSubjectId))[0];

    if (credential === undefined) return undefined;

    const snapshot = yield* mapping.credential.decode({
      moduleId: input.moduleId,
      subject,
      identifier,
      credential,
    });

    if (!sameSnapshot(snapshot, input.credential)) return undefined;
    identifierCondition = identifierCurrentCondition(
      mapping,
      input,
      nativeSubjectId,
      identifier[mapping.identifier.verifiedAt],
    );
    const ic = identifierColumns(mapping);

    identifierCondition = and(
      identifierCondition,
      sql`exists(select 1 from ${mapping.identifier.table} where ${ic.namespace} = ${sql.param(input.credential.identifier.namespace, ic.namespace)} and ${ic.value} = ${sql.param(input.credential.identifier.value, ic.value)} and ${ic.subjectId} = ${sql.param(nativeSubjectId, ic.subjectId)} and ${ic.bindingRevision} = ${sql.param(input.credential.identifierBindingRevision, ic.bindingRevision)})`,
    )!;
  }

  const expected = [
    ...new Map(
      [
        ...input.expectedRevision.credentials,
        ...input.authorization.evidence.revision.credentials,
      ].map((item) => [item.credentialId, item]),
    ).values(),
  ].sort((left, right) => left.credentialId.localeCompare(right.credentialId));

  const ac = authorityColumns(mapping);

  const rows =
    expected.length === 0
      ? []
      : yield* database
          .select()
          .from(mapping.authorityCredential.table)
          .where(
            and(
              eq(ac.subjectId, nativeSubjectId),
              inArray(
                ac.credentialId,
                expected.map((item) => item.credentialId),
              ),
            ),
          );

  const sortedRows = [...rows].sort((left: any, right: any) =>
    String(left[mapping.authorityCredential.credentialId]).localeCompare(
      String(right[mapping.authorityCredential.credentialId]),
    ),
  );

  if (
    sortedRows.length !== expected.length ||
    sortedRows.some(
      (row: any, index) =>
        row[mapping.authorityCredential.credentialId] !== expected[index]!.credentialId ||
        row[mapping.authorityCredential.revision] !== expected[index]!.revision ||
        (mapping.authorityCredential.status !== undefined &&
          mapping.authorityCredential.isActiveStatus?.(row[mapping.authorityCredential.status]) !==
            true),
    )
  )
    return undefined;
  const requirement = yield* mapping.subject.decodeActionRequirement(subject, action);
  const engineNow = yield* readEngineNowMillis(mapping);

  if (
    !evidenceSatisfiedAt(
      input.authorization.evidence,
      input.authorization.requirement,
      engineNow,
    ) ||
    !evidenceSatisfiedAt(input.authorization.evidence, requirement, engineNow)
  )
    return undefined;
  if (
    input.invalidation.existingSessions === "immediate" &&
    mapping.sessionInvalidation !== "same-authority-immediate"
  )
    return undefined;
  const s = subjectColumns(mapping);

  const credentialConditions = expected.map(
    (item) =>
      sql`exists(select 1 from ${mapping.authorityCredential.table} where ${ac.subjectId} = ${sql.param(nativeSubjectId, ac.subjectId)} and ${ac.credentialId} = ${sql.param(item.credentialId, ac.credentialId)} and ${ac.revision} = ${sql.param(item.revision, ac.revision)}${ac.status === undefined ? sql`` : sql` and ${ac.status} = ${sql.param(mapping.authorityCredential.d1ActiveStatusValue, ac.status)}`})`,
  );

  return {
    nativeSubjectId,
    subject,
    requirement,
    identifierCondition,
    condition: balancedD1And(
      sql`exists(select 1 from ${mapping.subject.table} where ${s.id} = ${sql.param(nativeSubjectId, s.id)} and ${s.status} = ${sql.param(mapping.subject.d1ActiveStatusValue, s.status)} and ${s.securityRevision} = ${sql.param(input.expectedRevision.securityRevision, s.securityRevision)})`,
      identifierCondition,
      ...credentialConditions,
      assuranceCondition(mapping, input.authorization.evidence, input.authorization.requirement),
      assuranceCondition(mapping, input.authorization.evidence, requirement),
    )!,
  };
});

const commandAbsentCondition = (mapping: Mapping, moduleId: string, commandId: string) => {
  const c = commandColumns(mapping);

  return sql`not exists(select 1 from ${mapping.command.table} where ${c.moduleId} = ${sql.param(moduleId, c.moduleId)} and ${c.commandId} = ${sql.param(commandId, c.commandId)})`;
};

const credentialCurrentCondition = (
  mapping: Mapping,
  input: PasswordMutationInput,
  nativeSubjectId: unknown,
) => {
  const c = credentialColumns(mapping);

  return input.credential === undefined
    ? sql`false`
    : sql`exists(select 1 from ${mapping.credential.table} where ${c.moduleId} = ${sql.param(input.moduleId, c.moduleId)} and ${c.subjectId} = ${sql.param(nativeSubjectId, c.subjectId)} and ${c.credentialId} = ${sql.param(input.credential.credentialId, c.credentialId)} and ${c.credentialRevision} = ${sql.param(input.credential.credentialRevision, c.credentialRevision)} and ${c.verifierVersion} = ${sql.param(input.credential.verifierVersion, c.verifierVersion)} and ${c.verifier} = ${sql.param(Redacted.value(input.credential.verifier), c.verifier)} and ${c.normalization} = ${sql.param(input.credential.normalization, c.normalization)})`;
};

const mutationStatements = Effect.fn(function* (
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
  const database = yield* CurrentD1PlanningDatabase;
  const c = credentialColumns(mapping);
  const s = subjectColumns(mapping);
  const ac = authorityColumns(mapping);

  return [
    yield* statement(
      database
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
        ),
    ),
    yield* statement(
      database
        .update(mapping.subject.table)
        .set(updateValues([[mapping.subject.securityRevision, revisions.nextSecurityRevision]]))
        .where(
          and(
            eq(s.id, nativeSubjectId),
            eq(s.securityRevision, input.expectedRevision.securityRevision),
          ),
        ),
    ),
    yield* statement(
      database
        .update(mapping.authorityCredential.table)
        .set(mapping.authorityCredential.encodeRevision(revisions.credentialRevision))
        .where(
          and(
            eq(ac.subjectId, nativeSubjectId),
            eq(ac.credentialId, input.credential!.credentialId),
            eq(ac.revision, input.credential!.credentialRevision),
          ),
        ),
    ),
    yield* statement(
      database.insert(mapping.command.table).values(
        mapping.command.encodeInsert({
          moduleId: input.moduleId,
          commandId: input.commandId,
          action: input.authorization.challenge.action,
          bindingDigest: input.authorization.challenge.bindingDigest,
          decision: "changed",
          retentionUntilMillis: now + mapping.commandRetentionMillis,
        }),
      ),
    ),
  ];
});

const replacementApplied = (
  mapping: Mapping,
  input: PasswordMutationInput,
  nativeSubjectId: unknown,
  revisions: {
    readonly credentialRevision: SecurityRevision;
    readonly verifierVersion: SecurityRevision;
    readonly nextSecurityRevision: SecurityRevision;
  },
  now: number,
  identifierCondition: SQL,
) => {
  const c = credentialColumns(mapping);
  const s = subjectColumns(mapping);
  const ac = authorityColumns(mapping);
  const mc = commandColumns(mapping);

  return and(
    sql`exists(select 1 from ${mapping.credential.table} where ${c.moduleId} = ${sql.param(input.moduleId, c.moduleId)} and ${c.subjectId} = ${sql.param(nativeSubjectId, c.subjectId)} and ${c.credentialId} = ${sql.param(input.credential!.credentialId, c.credentialId)} and ${c.credentialRevision} = ${sql.param(revisions.credentialRevision, c.credentialRevision)} and ${c.verifierVersion} = ${sql.param(revisions.verifierVersion, c.verifierVersion)} and ${c.verifier} = ${sql.param(Redacted.value(input.replacement.verifier), c.verifier)} and ${c.normalization} = ${sql.param(input.replacement.normalization, c.normalization)})`,
    sql`exists(select 1 from ${mapping.subject.table} where ${s.id} = ${sql.param(nativeSubjectId, s.id)} and ${s.securityRevision} = ${sql.param(revisions.nextSecurityRevision, s.securityRevision)} and ${s.status} = ${sql.param(mapping.subject.d1ActiveStatusValue, s.status)})`,
    sql`exists(select 1 from ${mapping.authorityCredential.table} where ${ac.subjectId} = ${sql.param(nativeSubjectId, ac.subjectId)} and ${ac.credentialId} = ${sql.param(input.credential!.credentialId, ac.credentialId)} and ${ac.revision} = ${sql.param(revisions.credentialRevision, ac.revision)}${ac.status === undefined ? sql`` : sql` and ${ac.status} = ${sql.param(mapping.authorityCredential.d1ActiveStatusValue, ac.status)}`})`,
    sql`exists(select 1 from ${mapping.command.table} where ${mc.moduleId} = ${sql.param(input.moduleId, mc.moduleId)} and ${mc.commandId} = ${sql.param(input.commandId, mc.commandId)} and ${mc.bindingDigest} = ${sql.param(input.authorization.challenge.bindingDigest, mc.bindingDigest)} and ${mc.action} = ${sql.param(input.authorization.challenge.action, mc.action)} and ${mc.decision} = ${sql.param("changed", mc.decision)} and ${mc.retentionUntil} = ${sql.param(mapping.encodeInstant(now + mapping.commandRetentionMillis), mc.retentionUntil)})`,
    identifierCondition,
    sql`true`,
  )!;
};

const compileAddMutation = Effect.fn("DrizzleD1Password.compileAddMutation")(function* (
  mapping: Mapping,
  input: PasswordMutationInput,
  revisions: {
    readonly credentialId: string;
    readonly credentialRevision: SecurityRevision;
    readonly verifierVersion: SecurityRevision;
    readonly nextSecurityRevision: SecurityRevision;
  },
) {
  const database = yield* CurrentD1PlanningDatabase;

  const { credentialId, credentialRevision, verifierVersion, nextSecurityRevision } = revisions;

  const authority = yield* readAuthority(mapping, input, "add-password");

  if (authority === undefined) return undefined;
  const now = yield* readEngineNowMillis(mapping);
  const c = credentialColumns(mapping);
  const s = subjectColumns(mapping);
  const ac = authorityColumns(mapping);
  const mc = commandColumns(mapping);
  const marker = `effect-auth-password-guard:add:${input.commandId}`;
  const absent = sql`not exists(select 1 from ${mapping.credential.table} where ${c.moduleId} = ${sql.param(input.moduleId, c.moduleId)} and ${c.subjectId} = ${sql.param(authority.nativeSubjectId, c.subjectId)})`;

  const guard = and(
    authority.condition,
    absent,
    commandAbsentCondition(mapping, input.moduleId, input.commandId),
  )!;

  const appliedCondition = and(
    sql`exists(select 1 from ${mapping.credential.table} where ${c.moduleId} = ${sql.param(input.moduleId, c.moduleId)} and ${c.subjectId} = ${sql.param(authority.nativeSubjectId, c.subjectId)} and ${c.credentialId} = ${sql.param(credentialId, c.credentialId)} and ${c.credentialRevision} = ${sql.param(credentialRevision, c.credentialRevision)} and ${c.verifierVersion} = ${sql.param(verifierVersion, c.verifierVersion)} and ${c.verifier} = ${sql.param(Redacted.value(input.replacement.verifier), c.verifier)} and ${c.normalization} = ${sql.param(input.replacement.normalization, c.normalization)})`,
    sql`exists(select 1 from ${mapping.authorityCredential.table} where ${ac.subjectId} = ${sql.param(authority.nativeSubjectId, ac.subjectId)} and ${ac.credentialId} = ${sql.param(credentialId, ac.credentialId)} and ${ac.revision} = ${sql.param(credentialRevision, ac.revision)}${ac.status === undefined ? sql`` : sql` and ${ac.status} = ${sql.param(mapping.authorityCredential.d1ActiveStatusValue, ac.status)}`})`,
    sql`exists(select 1 from ${mapping.subject.table} where ${s.id} = ${sql.param(authority.nativeSubjectId, s.id)} and ${s.securityRevision} = ${sql.param(nextSecurityRevision, s.securityRevision)} and ${s.status} = ${sql.param(mapping.subject.d1ActiveStatusValue, s.status)})`,
    sql`exists(select 1 from ${mapping.command.table} where ${mc.moduleId} = ${sql.param(input.moduleId, mc.moduleId)} and ${mc.commandId} = ${sql.param(input.commandId, mc.commandId)} and ${mc.bindingDigest} = ${sql.param(input.authorization.challenge.bindingDigest, mc.bindingDigest)} and ${mc.action} = ${sql.param("add-password", mc.action)} and ${mc.decision} = ${sql.param("changed", mc.decision)} and ${mc.retentionUntil} = ${sql.param(mapping.encodeInstant(now + mapping.commandRetentionMillis), mc.retentionUntil)})`,
  )!;

  const statements: Statement<any>[] = [
    yield* assertion(guard, marker),
    yield* statement(
      database.insert(mapping.credential.table).values(
        mapping.credential.encodeInsert({
          moduleId: input.moduleId,
          subjectId: authority.nativeSubjectId,
          credentialId,
          credentialRevision,
          verifierVersion,
          replacement: input.replacement,
        }),
      ),
    ),
    yield* statement(
      database.insert(mapping.authorityCredential.table).values(
        mapping.authorityCredential.encodeInsert({
          subjectId: authority.nativeSubjectId,
          credentialId,
          revision: credentialRevision,
        }),
      ),
    ),
    yield* statement(
      database
        .update(mapping.subject.table)
        .set(updateValues([[mapping.subject.securityRevision, nextSecurityRevision]]))
        .where(
          and(
            eq(s.id, authority.nativeSubjectId),
            eq(s.securityRevision, input.expectedRevision.securityRevision),
          ),
        ),
    ),
    yield* statement(
      database.insert(mapping.command.table).values(
        mapping.command.encodeInsert({
          moduleId: input.moduleId,
          commandId: input.commandId,
          action: "add-password",
          bindingDigest: input.authorization.challenge.bindingDigest,
          decision: "changed",
          retentionUntilMillis: now + mapping.commandRetentionMillis,
        }),
      ),
    ),
    yield* assertion(appliedCondition, marker),
  ];

  return {
    statements,
    appliedCondition,
    marker,
    retryable: (cause: unknown) => isGuardFailure(cause, marker),
  };
});

const makePasswordPlans = (
  mapping: Mapping,
  proofMapping?: D1ProofPersistenceMapping<
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any
  >,
) => {
  const run = <A, E, R>(plan: Effect.Effect<Planned<A>, E, R>) =>
    Effect.gen(function* () {
      if (!validConstraints(mapping)) return yield* unavailable();

      return yield* plan;
    });

  return {
    findCredential: (uncaptured: Parameters<PasswordPersistence["Service"]["findCredential"]>[0]) =>
      Effect.gen(function* () {
        if (!validConstraints(mapping)) return yield* unavailable();
        const input = { ...uncaptured, identifier: { ...uncaptured.identifier } };
        const database = yield* CurrentD1PlanningDatabase;
        const identifierRow = (yield* readIdentifier(mapping, input.identifier))[0];

        if (identifierRow === undefined || !mapping.identifier.isCurrent(identifierRow))
          return Option.none();
        const nativeId = identifierRow[mapping.identifier.subjectId];

        const sc = subjectColumns(mapping),
          ic = identifierColumns(mapping),
          cc = credentialColumns(mapping);

        // Bind the same native ID through each column's codec, then inspect one coherent snapshot.
        const rows = yield* database
          .select({
            subject: getTableColumns(mapping.subject.table),
            identifier: getTableColumns(mapping.identifier.table),
            credential: getTableColumns(mapping.credential.table),
          })
          .from(mapping.subject.table)
          .innerJoin(
            mapping.identifier.table,
            and(
              eq(ic.namespace, input.identifier.namespace),
              eq(ic.value, input.identifier.value),
              eq(ic.subjectId, nativeId),
            ),
          )
          .innerJoin(
            mapping.credential.table,
            and(eq(cc.moduleId, input.moduleId), eq(cc.subjectId, nativeId)),
          )
          .where(eq(sc.id, nativeId));

        if (rows.length !== 1) return Option.none();
        const row = rows[0]!;

        if (
          !mapping.subject.isActiveStatus(row.subject[mapping.subject.status]) ||
          !mapping.identifier.isCurrent(row.identifier) ||
          !mapping.subjectId.equals(nativeId, row.subject[mapping.subject.id]) ||
          !mapping.subjectId.equals(nativeId, row.identifier[mapping.identifier.subjectId]) ||
          !mapping.subjectId.equals(nativeId, row.credential[mapping.credential.subjectId])
        )
          return Option.none();

        const credential = yield* mapping.credential
          .decode({ moduleId: input.moduleId, ...row })
          .pipe(Effect.flatMap(snapshotPasswordCredential));

        return input.subjectId !== undefined && credential.revision.subjectId !== input.subjectId
          ? Option.none()
          : Option.some(credential);
      }),
    rehashIfCurrent: (input: Parameters<PasswordPersistence["Service"]["rehashIfCurrent"]>[0]) =>
      run(
        Effect.gen(function* () {
          const nextVerifier = Redacted.make(
            yield* Schema.decodeEffect(EncodedPasswordHash)(Redacted.value(input.nextVerifier)),
          );

          const credential = yield* snapshotPasswordCredential(input.credential);
          const database = yield* CurrentD1PlanningDatabase;
          const nativeId = yield* mapping.subjectId.toNative(credential.revision.subjectId);
          const version = yield* allocate(mapping.allocateRevision, mapping.allocateRevisionSync);

          if (version === credential.verifierVersion) return yield* unavailable();
          const encoded = mapping.credential.encodeVerifier(nextVerifier, version);

          const values = {
            [mapping.credential.verifier]: encoded[mapping.credential.verifier],
            [mapping.credential.verifierVersion]: encoded[mapping.credential.verifierVersion],
          };

          if (Object.values(values).some((value) => value === undefined))
            return yield* unavailable();
          const c = credentialColumns(mapping);

          return {
            receipt: undefined,
            statements: [
              yield* statement(
                database
                  .update(mapping.credential.table)
                  .set(values)
                  .where(
                    and(
                      eq(c.moduleId, credential.moduleId),
                      eq(c.subjectId, nativeId),
                      eq(c.credentialId, credential.credentialId),
                      ...(
                        [
                          [c.moduleId, credential.moduleId],
                          [c.subjectId, nativeId],
                          [c.credentialId, credential.credentialId],
                          [c.credentialRevision, credential.credentialRevision],
                          [c.verifierVersion, credential.verifierVersion],
                          [c.verifier, Redacted.value(credential.verifier)],
                          [c.normalization, credential.normalization],
                        ] as const
                      ).map(([column, value]) =>
                        typeof value === "string"
                          ? sql`cast(${column} as blob) = cast(${sql.param(value, column)} as blob)`
                          : eq(column, value),
                      ),
                    ),
                  ),
              ),
            ],
          };
        }),
      ),
    readForSubject: (input: Parameters<PasswordPersistence["Service"]["readForSubject"]>[0]) =>
      Effect.gen(function* () {
        const database = yield* CurrentD1PlanningDatabase;

        if (yield* hasCommitScope) return yield* unavailable();
        const nativeSubjectId = yield* mapping.subjectId.toNative(input.subjectId);
        const subject = (yield* readSubjectNative(mapping, nativeSubjectId))[0];

        if (
          subject === undefined ||
          !mapping.subject.isActiveStatus(subject[mapping.subject.status])
        )
          return Option.none();

        const credential = (yield* readCredentialNative(
          mapping,
          input.moduleId,
          nativeSubjectId,
        ))[0];

        if (credential === undefined) return Option.none();
        const ic = identifierColumns(mapping);

        const identifiers = yield* database
          .select()
          .from(mapping.identifier.table)
          .where(eq(ic.subjectId, nativeSubjectId));

        const identifier = identifiers.find((row: any) => mapping.identifier.isCurrent(row));

        if (identifier === undefined) return Option.none();

        return Option.some(
          yield* mapping.credential
            .decode({ moduleId: input.moduleId, subject, identifier, credential })
            .pipe(Effect.flatMap(snapshotPasswordCredential)),
        );
      }),
    recoveryTarget: (input: Parameters<PasswordPersistence["Service"]["recoveryTarget"]>[0]) =>
      Effect.gen(function* () {
        if (yield* hasCommitScope) return yield* unavailable();
        const resolved = yield* resolveCredential(mapping, input.moduleId, input.identifier);

        return resolved?.snapshot === undefined ||
          resolved.snapshot.identifierVerifiedAtMillis === undefined
          ? Option.none()
          : Option.some(resolved.snapshot);
      }),
    addIfAbsent: <A>(
      uncaptured: Parameters<PasswordPersistence["Service"]["addIfAbsent"]>[0],
      prepare: PlanPrepare<PasswordPersistence["Service"]["addIfAbsent"], A>,
    ) =>
      Effect.gen(function* () {
        const input = yield* snapshotMutationInput(uncaptured);

        const credentialId = yield* allocate(
          mapping.allocateCredentialId,
          mapping.allocateCredentialIdSync,
        );

        const credentialRevision = yield* allocate(
          mapping.allocateRevision,
          mapping.allocateRevisionSync,
        );

        const verifierVersion = yield* allocate(
          mapping.allocateRevision,
          mapping.allocateRevisionSync,
        );

        const nextSecurityRevision = yield* allocateNextSecurityRevision(
          mapping,
          input.expectedRevision.securityRevision,
        );

        if (nextSecurityRevision === input.expectedRevision.securityRevision)
          return yield* unavailable();

        return yield* run(
          Effect.gen(function* () {
            const journal = yield* CurrentCommitJournal;

            const compiled = yield* compileAddMutation(mapping, input, {
              credentialId,
              credentialRevision,
              verifierVersion,
              nextSecurityRevision,
            });

            if (compiled === undefined)
              return { receipt: prepare("rejected", journal), statements: [] };

            return {
              receipt: prepare("changed", journal),
              statements: compiled.statements,
              postconditions: [yield* assertion(compiled.appliedCondition, compiled.marker)],
              retryable: compiled.retryable,
            };
          }),
        );
      }),
    replaceIfCurrent: <A>(
      uncaptured: Parameters<PasswordPersistence["Service"]["replaceIfCurrent"]>[0],
      prepare: PlanPrepare<PasswordPersistence["Service"]["replaceIfCurrent"], A>,
    ) =>
      Effect.flatMap(snapshotMutationInput(uncaptured), (input) =>
        replacementPlan(mapping, proofMapping, input, prepare, "change-password"),
      ),
    checkReset: (input: Parameters<PasswordPersistence["Service"]["checkReset"]>[0]) =>
      proofMapping === undefined
        ? Effect.fail(unavailable())
        : Effect.gen(function* () {
            if (yield* hasCommitScope) return yield* unavailable();
            if (
              input.moduleId.length <= "/reset".length ||
              !input.moduleId.endsWith("/reset") ||
              input.purpose !== "password-reset" ||
              input.binding._tag !== "Subject"
            )
              return false;
            const binding = input.binding;

            const resolved = yield* resolveCredential(
              mapping,
              input.moduleId.slice(0, -"/reset".length),
              binding.identifier,
              binding.revision.subjectId,
            );

            const current =
              resolved?.snapshot !== undefined &&
              resolved.snapshot.revision.securityRevision === binding.revision.securityRevision &&
              binding.revision.credentials.every((item) =>
                resolved.snapshot!.revision.credentials.some(
                  (current) =>
                    current.credentialId === item.credentialId &&
                    current.revision === item.revision,
                ),
              );

            return current ? yield* probeProofCompletion(proofMapping, input) : false;
          }),
    resetWithProof: <A>(
      uncaptured: Parameters<PasswordPersistence["Service"]["resetWithProof"]>[0],
      prepare: PlanPrepare<PasswordPersistence["Service"]["resetWithProof"], A>,
    ) =>
      proofMapping === undefined
        ? Effect.fail(unavailable())
        : Effect.flatMap(snapshotMutationInput(uncaptured), (captured) =>
            replacementPlan(
              mapping,
              proofMapping,
              Object.freeze({ ...captured, completion: uncaptured.completion }),
              prepare,
              "reset-password",
            ),
          ),
  };
};

const compileReplacementMutation = Effect.fn("DrizzleD1Password.compileReplacementMutation")(
  function* (
    mapping: Mapping,
    input: PasswordMutationInput,
    action: "change-password" | "reset-password",
    revisions: {
      readonly credentialRevision: SecurityRevision;
      readonly verifierVersion: SecurityRevision;
      readonly nextSecurityRevision: SecurityRevision;
    },
  ) {
    const { credentialRevision, verifierVersion, nextSecurityRevision } = revisions;
    const authority = yield* readAuthority(mapping, input, action);

    const current =
      authority === undefined || input.credential === undefined
        ? undefined
        : (yield* readCredentialNative(mapping, input.moduleId, authority.nativeSubjectId))[0];

    const currentMatches =
      current !== undefined &&
      current[mapping.credential.credentialId] === input.credential!.credentialId &&
      current[mapping.credential.credentialRevision] === input.credential!.credentialRevision &&
      current[mapping.credential.verifierVersion] === input.credential!.verifierVersion &&
      current[mapping.credential.verifier] === Redacted.value(input.credential!.verifier) &&
      current[mapping.credential.normalization] === input.credential!.normalization;

    if (authority === undefined || !currentMatches) return undefined;
    const now = yield* readEngineNowMillis(mapping);

    const guard = and(
      authority.condition,
      credentialCurrentCondition(mapping, input, authority.nativeSubjectId),
      commandAbsentCondition(mapping, input.moduleId, input.commandId),
    )!;

    const marker = `effect-auth-password-guard:${action}:${input.commandId}`;

    const protectedMutation: D1ProtectedProofMutation = {
      statements: [
        yield* assertion(guard, marker),
        ...(yield* mutationStatements(
          mapping,
          input,
          authority.nativeSubjectId,
          { credentialRevision, verifierVersion, nextSecurityRevision },
          now,
        )),
      ],
      appliedCondition: replacementApplied(
        mapping,
        input,
        authority.nativeSubjectId,
        {
          credentialRevision,
          verifierVersion,
          nextSecurityRevision,
        },
        now,
        authority.identifierCondition,
      ),
    };

    return { protectedMutation, marker };
  },
);

const replacementPlan = Effect.fn("Drizzle.replacementPlan")(function* <A>(
  mapping: Mapping,
  proofMapping:
    | D1ProofPersistenceMapping<any, any, any, any, any, any, any, any, any, any, any, any>
    | undefined,
  input: PasswordMutationInput & { readonly completion?: any },
  prepare: PreparePasswordCommit<PasswordMutationDecision, A>,
  action: "change-password" | "reset-password",
) {
  const credentialRevision = yield* allocate(
    mapping.allocateRevision,
    mapping.allocateRevisionSync,
  );

  const verifierVersion = yield* allocate(mapping.allocateRevision, mapping.allocateRevisionSync);

  const nextSecurityRevision = yield* allocateNextSecurityRevision(
    mapping,
    input.expectedRevision.securityRevision,
  );

  if (
    nextSecurityRevision === input.expectedRevision.securityRevision ||
    (input.credential !== undefined && credentialRevision === input.credential.credentialRevision)
  )
    return yield* unavailable();

  const journal = yield* CurrentCommitJournal;

  const compiledMutation = yield* compileReplacementMutation(mapping, input, action, {
    credentialRevision,
    verifierVersion,
    nextSecurityRevision,
  });

  if (compiledMutation === undefined)
    return { receipt: prepare("rejected", journal), statements: [] };
  const { protectedMutation, marker } = compiledMutation;

  if (action === "reset-password") {
    if (
      proofMapping === undefined ||
      input.completion === undefined ||
      !completionMatchesPassword(
        input as PasswordMutationInput & { readonly completion: ProofCompletionPlan },
      )
    )
      return { receipt: prepare("rejected", journal), statements: [] };
    let passwordReceipt: PreparedCommit<A> | undefined;

    const compiled = yield* compileD1ProofCompletionPlan(
      proofMapping,
      input.completion,
      protectedMutation,
      (decision: ProofCompletionDecision) => {
        passwordReceipt = prepare(decision === "completed" ? "changed" : "rejected", journal);

        return decision;
      },
    );

    return {
      receipt: passwordReceipt ?? prepare("rejected", journal),
      statements: compiled.statements,
      ...(compiled.postconditions === undefined ? {} : { postconditions: compiled.postconditions }),
      retryable: (cause: unknown) =>
        isGuardFailure(cause, marker) ||
        isGuardFailure(
          cause,
          `effect-auth-proof-guard:complete:${input.completion.input.continuationId}`,
        ) ||
        isGuardFailure(
          cause,
          `effect-auth-proof-guard:protected:${input.completion.input.continuationId}`,
        ),
    };
  }

  const applied = yield* assertion(protectedMutation.appliedCondition, marker);

  return {
    receipt: prepare("changed", journal),
    statements: [...protectedMutation.statements, applied],
    postconditions: [applied],
    retryable: (cause: unknown) => isGuardFailure(cause, marker),
  };
});

export const makeD1PasswordPersistenceServices = Effect.fnUntraced(function* <
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  M extends AnySQLiteTable,
  NativeId,
>(
  mapping: D1PasswordPersistenceMapping<S, I, C, AC, M, NativeId>,
  proofMapping?: D1ProofPersistenceMapping<
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any
  >,
) {
  const database = yield* DatabaseService;

  yield* validateDrizzleStorage({ ...mapping, proof: proofMapping }).pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(DatabaseService)),
    Effect.mapError(unavailable),
  );

  const hooks = yield* LifecycleHooks;
  const plans = makePasswordPlans(mapping as unknown as Mapping, proofMapping);

  const standalone = Effect.gen(function* () {
    if (yield* hasCommitScope) return yield* unavailable();
    yield* requireStandalone(unavailable, database.$client.transactionService);
  });

  const run = <Out, Err, Env>(plan: Effect.Effect<Planned<Out>, Err, Env>) =>
    Effect.gen(function* () {
      yield* standalone;

      return yield* executeStandalone(plan, 2);
    }).pipe(
      Effect.provideService(CurrentD1PlanningDatabase, database),
      Effect.provideService(LifecycleHooks, hooks),
    );

  const service: PasswordPersistence["Service"] = {
    findCredential: (input) =>
      standalone.pipe(
        Effect.andThen(plans.findCredential(input)),
        Effect.provideService(CurrentD1PlanningDatabase, database),
        translateFailure,
      ),
    rehashIfCurrent: (input) => run(plans.rehashIfCurrent(input)).pipe(translateFailure),
    readForSubject: (input) =>
      plans
        .readForSubject(input)
        .pipe(
          Effect.provideService(CurrentD1PlanningDatabase, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
    recoveryTarget: (input) =>
      plans
        .recoveryTarget(input)
        .pipe(
          Effect.provideService(CurrentD1PlanningDatabase, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
    addIfAbsent: (input, prepare) => run(plans.addIfAbsent(input, prepare)).pipe(translateFailure),
    replaceIfCurrent: (input, prepare) =>
      run(plans.replaceIfCurrent(input, prepare)).pipe(translateFailure),
    checkReset: (input) =>
      plans
        .checkReset(input)
        .pipe(
          Effect.provideService(CurrentD1PlanningDatabase, database),
          Effect.provideService(LifecycleHooks, hooks),
          translateFailure,
        ),
    resetWithProof: (input, prepare) =>
      run(plans.resetWithProof(input, prepare)).pipe(translateFailure),
  };

  return { passwordPersistence: service };
});

type CoordinatorError<E> = E | PasswordUnavailable | HookConfigurationError;

/**
 * Owns one password transition plus application statements in one D1 batch.
 * The owner Effect is invoked once and is never replayed after an ambiguous or
 * guarded batch failure. Standalone adapter-owned commands may replan boundedly.
 */
export function coordinateD1PasswordPersistence<
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  M extends AnySQLiteTable,
  NativeId,
  A,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: D1PasswordPersistenceMapping<S, I, C, AC, M, NativeId>;
    readonly proofMapping?:
      | D1ProofPersistenceMapping<any, any, any, any, any, any, any, any, any, any, any, any>
      | undefined;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  CoordinatorError<E> | DatabaseError,
  Exclude<R, PasswordPersistence | D1BatchStatements> | LifecycleHooks | DatabaseRequirements
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    Effect.gen(function* () {
      yield* validateDrizzleStorage({
        ...options.mapping,
        proof: options.proofMapping,
      }).pipe(Effect.mapError(unavailable));
      const hooks = yield* LifecycleHooks;

      if (yield* hasCommitScope) return yield* unavailable();

      const result = yield* coordinateCommit(
        () =>
          Effect.gen(function* () {
            const statements: Statement<any>[] = [];
            let mutation: Planned<any> | undefined;

            const nativeCollector = D1BatchStatements.of({
              append: (statement) => Effect.sync(() => statements.push(statement)),
            });

            const owner = yield* makeD1Owner(unavailable()).pipe(
              Effect.provideService(D1BatchStatements, nativeCollector),
            );

            const plans = makePasswordPlans(
              options.mapping as unknown as Mapping,
              options.proofMapping,
            );

            const run = <Out, Err, Env>(plan: Effect.Effect<Planned<Out>, Err, Env>) =>
              coordinateCommit(
                () =>
                  Effect.gen(function* () {
                    const journal = yield* CurrentCommitJournal;
                    const planned = yield* plan;

                    yield* owner.check;
                    if (mutation !== undefined) return yield* unavailable();
                    const guarded = { ...planned, journalGuard: journal.prepare(undefined) };

                    mutation = guarded;
                    statements.push(...guarded.statements);

                    return guarded.receipt;
                  }),
                { mode: "batch" },
              ).pipe(
                Effect.map((result) => result.value),
                Effect.provideService(CurrentD1PlanningDatabase, database),
                Effect.provideService(LifecycleHooks, hooks),
              );

            const service: PasswordPersistence["Service"] = {
              findCredential: (input) =>
                owner.run(
                  plans
                    .findCredential(input)
                    .pipe(
                      Effect.provideService(CurrentD1PlanningDatabase, database),
                      translateFailure,
                    ),
                ),
              rehashIfCurrent: (input) =>
                owner.run(run(plans.rehashIfCurrent(input)).pipe(translateFailure)),
              readForSubject: (input) =>
                owner.run(
                  plans
                    .readForSubject(input)
                    .pipe(
                      Effect.provideService(CurrentD1PlanningDatabase, database),
                      Effect.provideService(LifecycleHooks, hooks),
                      translateFailure,
                    ),
                ),
              recoveryTarget: (input) =>
                owner.run(
                  plans
                    .recoveryTarget(input)
                    .pipe(
                      Effect.provideService(CurrentD1PlanningDatabase, database),
                      Effect.provideService(LifecycleHooks, hooks),
                      translateFailure,
                    ),
                ),
              addIfAbsent: (input, prepare) =>
                owner.run(run(plans.addIfAbsent(input, prepare)).pipe(translateFailure)),
              replaceIfCurrent: (input, prepare) =>
                owner.run(run(plans.replaceIfCurrent(input, prepare)).pipe(translateFailure)),
              checkReset: (input) =>
                owner.run(
                  plans
                    .checkReset(input)
                    .pipe(
                      Effect.provideService(CurrentD1PlanningDatabase, database),
                      Effect.provideService(LifecycleHooks, hooks),
                      translateFailure,
                    ),
                ),
              resetWithProof: (input, prepare) =>
                owner.run(run(plans.resetWithProof(input, prepare)).pipe(translateFailure)),
            };

            const provided = Context.make(PasswordPersistence, service).pipe(
              Context.add(D1BatchStatements, owner.collector),
            );

            const value = yield* owner.close(Effect.provideContext(body, provided));

            if (mutation?.journalGuard !== undefined) {
              const status = yield* Effect.result(mutation.journalGuard.read);

              if (status._tag === "Success" || status.failure._tag !== "CommitPending")
                return yield* unavailable();
            }
            // Re-assert the password's final state after application statements.
            yield* database.$client
              .batch([...statements, ...(mutation?.postconditions ?? [])])
              .pipe(
                Effect.catchCause((cause) =>
                  Effect.failCause(
                    Cause.map(cause, (error) =>
                      everyFailureMatches(cause, mutation?.retryable) ? unavailable() : error,
                    ),
                  ),
                ),
                translateFailure,
              );

            return value;
          }),
        { mode: "batch" },
      ).pipe(Effect.provideService(LifecycleHooks, hooks));

      return result.value;
    }).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

const registrationRows = Effect.fn("Drizzle.registrationRows")(function* <Registration>(
  mapping: RegistrationMapping<Registration>,
  moduleId: string,
  requestId: string,
) {
  const database = yield* CurrentD1PlanningDatabase;

  const module = column(mapping.registration.table, mapping.registration.moduleId);
  const request = column(mapping.registration.table, mapping.registration.requestId);

  return yield* database
    .select()
    .from(mapping.registration.table)
    .where(and(eq(module, moduleId), eq(request, requestId)))
    .limit(1);
});

const registrationIdentifierRows = Effect.fn("Drizzle.registrationIdentifierRows")(function* <
  Registration,
>(mapping: RegistrationMapping<Registration>, identifier: LoginIdentifier) {
  const database = yield* CurrentD1PlanningDatabase;

  const namespace = column(mapping.identifier.table, mapping.identifier.namespace);
  const value = column(mapping.identifier.table, mapping.identifier.value);

  return yield* database
    .select()
    .from(mapping.identifier.table)
    .where(and(eq(namespace, identifier.namespace), eq(value, identifier.value)))
    .limit(1);
});

const planRegistration = Effect.fn("Drizzle.planRegistration")(function* <Registration, A>(
  mapping: RegistrationMapping<Registration>,
  input: {
    readonly moduleId: string;
    readonly requestId: string;
    readonly identifier: LoginIdentifier;
    readonly registration: Registration;
    readonly replacement: PasswordMutationInput["replacement"];
  },
  allocated: {
    readonly credentialId: string;
    readonly securityRevision: SecurityRevision;
    readonly identifierRevision: SecurityRevision;
    readonly credentialRevision: SecurityRevision;
    readonly verifierVersion: SecurityRevision;
    readonly nativeSubjectId?: unknown;
    readonly recoveryReference?: any;
  },
  prepare: PreparePasswordCommit<import("@yielded/auth/Password").PasswordRegistrationDecision, A>,
) {
  const database = yield* CurrentD1PlanningDatabase;
  const journal = yield* CurrentCommitJournal;

  const existing = (yield* registrationRows(mapping, input.moduleId, input.requestId))[0];

  if (existing !== undefined)
    return {
      receipt: prepare(yield* mapping.registration.decodeReplay(existing), journal),
      statements: [],
    };

  const intent = {
    moduleId: input.moduleId,
    requestId: input.requestId,
    identifier: input.identifier,
    registration: input.registration,
    replacement: input.replacement,
  };

  if (mapping.mode === "pending") {
    if (allocated.recoveryReference === undefined) return yield* unavailable();

    return {
      receipt: prepare({ _tag: "Pending", reference: allocated.recoveryReference }, journal),
      statements: [
        yield* statement(
          database.insert(mapping.registration.table).values(
            mapping.registration.encodeInsert(intent, {
              state: "pending",
              recoveryReference: allocated.recoveryReference,
            }),
          ),
        ),
      ],
      retryable: (cause: unknown) => isMappedConstraintConflict(mapping.isRequestConflict, cause),
    };
  }
  if (mapping.provisioning.idMode === "generated" || allocated.nativeSubjectId === undefined)
    return yield* unavailable();
  if ((yield* registrationIdentifierRows(mapping, input.identifier)).length > 0)
    return { receipt: prepare({ _tag: "Suppressed" }, journal), statements: [] };
  const nativeSubjectId = allocated.nativeSubjectId;
  const subjectId = yield* mapping.subjectId.toSubject(nativeSubjectId);

  return {
    receipt: prepare({ _tag: "Created", subjectId }, journal),
    statements: [
      yield* statement(
        database.insert(mapping.subject.table).values(
          mapping.provisioning.encodeSubjectInsert(intent, {
            nativeSubjectId,
            securityRevision: allocated.securityRevision,
          }),
        ),
      ),
      yield* statement(
        database
          .insert(mapping.identifier.table)
          .values(
            mapping.identifier.encodeInitialInsert(
              input.identifier,
              nativeSubjectId,
              allocated.identifierRevision,
            ),
          ),
      ),
      yield* statement(
        database.insert(mapping.credential.table).values(
          mapping.credential.encodeInsert({
            moduleId: input.moduleId,
            subjectId: nativeSubjectId,
            credentialId: allocated.credentialId,
            credentialRevision: allocated.credentialRevision,
            verifierVersion: allocated.verifierVersion,
            replacement: input.replacement,
          }),
        ),
      ),
      yield* statement(
        database.insert(mapping.authorityCredential.table).values(
          mapping.authorityCredential.encodeInsert({
            subjectId: nativeSubjectId,
            credentialId: allocated.credentialId,
            revision: allocated.credentialRevision,
          }),
        ),
      ),
      yield* statement(
        database.insert(mapping.registration.table).values(
          mapping.registration.encodeInsert(intent, {
            state: "created",
            nativeSubjectId,
          }),
        ),
      ),
    ],
    retryable: (cause: unknown) =>
      isMappedConstraintConflict(mapping.isRequestConflict, cause) ||
      isMappedConstraintConflict(mapping.isIdentifierConflict, cause),
  };
});

const allocateRegistration = <Registration>(mapping: RegistrationMapping<Registration>) =>
  Effect.gen(function* () {
    const credentialId = yield* allocate(
      mapping.allocateCredentialId,
      mapping.allocateCredentialIdSync,
    );

    const securityRevision = yield* allocate(
      mapping.allocateRevision,
      mapping.allocateRevisionSync,
    );

    const identifierRevision = yield* allocate(
      mapping.allocateRevision,
      mapping.allocateRevisionSync,
    );

    const credentialRevision = yield* allocate(
      mapping.allocateRevision,
      mapping.allocateRevisionSync,
    );

    const verifierVersion = yield* allocate(mapping.allocateRevision, mapping.allocateRevisionSync);

    const nativeSubjectId =
      mapping.mode !== "atomic" || mapping.provisioning.idMode === "generated"
        ? undefined
        : yield* allocate(
            mapping.provisioning.allocateSubjectId,
            mapping.provisioning.allocateSubjectIdSync,
          );

    const recoveryReference =
      mapping.mode === "pending"
        ? yield* allocate(mapping.allocateRecoveryReference, mapping.allocateRecoveryReferenceSync)
        : undefined;

    return {
      credentialId,
      securityRevision,
      identifierRevision,
      credentialRevision,
      verifierVersion,
      ...(nativeSubjectId === undefined ? {} : { nativeSubjectId }),
      ...(recoveryReference === undefined ? {} : { recoveryReference }),
    };
  });

const makeRegistrationPlans = <Registration>(mapping: RegistrationMapping<Registration>) => ({
  register: <A>(
    input: Parameters<PasswordRegistrationAuthority<Registration>["register"]>[0],
    prepare: PlanPrepare<PasswordRegistrationAuthority<Registration>["register"], A>,
  ) =>
    Effect.gen(function* () {
      if (!validRegistrationConstraints(mapping)) return yield* unavailable();
      if (mapping.mode === "atomic" && mapping.provisioning.idMode === "generated")
        return yield* unavailable();
      const allocated = yield* allocateRegistration(mapping);

      return yield* planRegistration(mapping, input, allocated, prepare);
    }),
});

export const makeD1PasswordRegistrationServices = Effect.fnUntraced(function* <
  Registration,
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  Rq extends AnySQLiteTable,
  NativeId,
>(mapping: PasswordRegistrationMapping<Registration, S, I, C, AC, Rq, NativeId>) {
  const database = yield* DatabaseService;

  yield* validateDrizzleStorage(mapping).pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(DatabaseService)),
    Effect.mapError(unavailable),
  );

  const hooks = yield* LifecycleHooks;
  const plans = makeRegistrationPlans(mapping as unknown as RegistrationMapping<Registration>);

  const run = <Out, Err, Env>(plan: Effect.Effect<Planned<Out>, Err, Env>) =>
    Effect.gen(function* () {
      if (yield* hasCommitScope) return yield* unavailable();

      return yield* executeStandalone(plan, 2);
    }).pipe(
      Effect.provideService(CurrentD1PlanningDatabase, database),
      Effect.provideService(LifecycleHooks, hooks),
    );

  const service: PasswordRegistrationAuthority<Registration> = {
    register: (input, prepare) => run(plans.register(input, prepare)).pipe(translateFailure),
  };

  return { registrationAuthority: service };
});

export function coordinateD1PasswordRegistration<
  TargetId,
  Registration,
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  Rq extends AnySQLiteTable,
  NativeId,
  A,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasswordRegistrationMapping<NoInfer<Registration>, S, I, C, AC, Rq, NativeId>;
    readonly target: SuppliedService<TargetId, PasswordRegistrationAuthority<Registration>>;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  CoordinatorError<E> | DatabaseError,
  Exclude<R, TargetId | D1BatchStatements> | LifecycleHooks | DatabaseRequirements
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    Effect.gen(function* () {
      yield* validateDrizzleStorage(options.mapping).pipe(Effect.mapError(unavailable));
      const hooks = yield* LifecycleHooks;

      if (yield* hasCommitScope) return yield* unavailable();

      const result = yield* coordinateCommit(
        () =>
          Effect.gen(function* () {
            const statements: Statement<any>[] = [];
            let mutation: Planned<any> | undefined;

            const nativeCollector = D1BatchStatements.of({
              append: (statement) => Effect.sync(() => statements.push(statement)),
            });

            const owner = yield* makeD1Owner(unavailable()).pipe(
              Effect.provideService(D1BatchStatements, nativeCollector),
            );

            const plans = makeRegistrationPlans(
              options.mapping as unknown as RegistrationMapping<Registration>,
            );

            const run = <Out, Err, Env>(plan: Effect.Effect<Planned<Out>, Err, Env>) =>
              coordinateCommit(
                () =>
                  Effect.gen(function* () {
                    const journal = yield* CurrentCommitJournal;
                    const planned = yield* plan;

                    yield* owner.check;
                    if (mutation !== undefined) return yield* unavailable();
                    const guarded = { ...planned, journalGuard: journal.prepare(undefined) };

                    mutation = guarded;
                    statements.push(...guarded.statements);

                    return guarded.receipt;
                  }),
                { mode: "batch" },
              ).pipe(
                Effect.map((result) => result.value),
                Effect.provideService(CurrentD1PlanningDatabase, database),
                Effect.provideService(LifecycleHooks, hooks),
              );

            const service: PasswordRegistrationAuthority<Registration> = {
              register: (input, prepare) =>
                owner.run(run(plans.register(input, prepare)).pipe(translateFailure)),
            };

            const provided = Context.make(options.target, service).pipe(
              Context.add(D1BatchStatements, owner.collector),
            );

            const value = yield* owner.close(Effect.provideContext(body, provided));

            if (mutation?.journalGuard !== undefined) {
              const status = yield* Effect.result(mutation.journalGuard.read);

              if (status._tag === "Success" || status.failure._tag !== "CommitPending")
                return yield* unavailable();
            }
            yield* database.$client.batch(statements).pipe(
              Effect.catchCause((cause) =>
                Effect.failCause(
                  Cause.map(cause, (error) =>
                    everyFailureMatches(cause, mutation?.retryable) ? unavailable() : error,
                  ),
                ),
              ),
              translateFailure,
            );

            return value;
          }),
        { mode: "batch" },
      ).pipe(Effect.provideService(LifecycleHooks, hooks));

      return result.value;
    }).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

/** Private prepared compiler seam: it never replays a caller or prepared callback. */
export const passwordD1Kernel = {
  statement,
  assertion,
  readEngineNowMillis,
  allocate,
  allocateNextSecurityRevision,
  subjectColumns,
  identifierColumns,
  credentialColumns,
  authorityColumns,
  readAuthority,
  assuranceCondition,
  credentialCurrentCondition,
  commandAbsentCondition,
  compileAddMutation,
  compileReplacementMutation,
  completionMatchesPassword,
  isGuardFailure,
};

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

const executeStandalone = <A, E, R>(
  plan: Effect.Effect<Planned<A>, E, R>,
  retries = 2,
): Effect.Effect<
  A,
  E | import("@yielded/auth/Hooks").HookConfigurationError | import("effect/sql/SqlError").SqlError,
  Exclude<R, CurrentCommitJournal> | CurrentD1PlanningDatabase | LifecycleHooks
> =>
  Effect.suspend(() => {
    let retryable: ((cause: unknown) => boolean) | undefined;

    const once = coordinateCommit(
      () =>
        Effect.gen(function* () {
          const database = yield* CurrentD1PlanningDatabase;
          const planned = yield* plan;

          retryable = planned.retryable;
          yield* database.$client.batch(planned.statements);

          return planned.receipt;
        }),
      { mode: "batch" },
    ).pipe(Effect.map((result) => result.value));

    return once.pipe(
      Effect.catchCause((cause) =>
        retries > 0 && everyFailureMatches(cause, retryable)
          ? executeStandalone(plan, retries - 1)
          : Effect.failCause(cause),
      ),
    );
  });
