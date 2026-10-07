import {
  type AnyEmailAddressMapping,
  type AnyEmailSignInMapping,
  requiredEmailAddressConstraints,
  requiredEmailSignInConstraints,
  validateEmailMutation,
} from "@yielded/auth-persistence/Adapter";
import {
  type EmailAddressMutation,
  type EmailAction,
  EmailUnavailable,
  snapshotEmailCredential,
  snapshotEmailRevision,
} from "@yielded/auth/Email";
import { hasCommitScope, HookConfigurationError } from "@yielded/auth/Hooks";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import { type SecurityRevision } from "@yielded/auth/Sessions";
import { and, eq, inArray, sql } from "drizzle-orm";
import { Cause, DateTime, Effect, Schema } from "effect";

import { CurrentEmailSql, type EmailSqlConfiguration, type CurrentAddress } from "./email-database";
import { column, updateValues } from "./model";
import type { NativeSqlDatabase, NativeSqlQuery } from "./native-database";
import { CurrentProofSql } from "./proof-database";
import { readSnapshot as readSnapshots, type SnapshotRead } from "./sql-snapshot";
/* oxlint-disable no-explicit-any -- native mappings erase foreign row shapes; persisted values use mapped codecs. */
type SignInMapping = AnyEmailSignInMapping;
type AddressMapping = AnyEmailAddressMapping;

export const unavailable = () => EmailUnavailable.make({});

export const translateFailure = <A, E, R>(
  effect: Effect.Effect<A, E, R>,
): Effect.Effect<A, EmailUnavailable, R> =>
  reportPersistenceFailure(
    effect,
    (error) =>
      Schema.is(EmailUnavailable)(error) ||
      Schema.is(ProofUnavailable)(error) ||
      Schema.is(HookConfigurationError)(error),
  ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, () => unavailable()))));

export const nowMillis = Effect.map(DateTime.now, DateTime.toEpochMillis);

export const selectRows = (query: NativeSqlQuery, locking: boolean) =>
  locking && typeof query.for === "function" ? query.for("update") : query;

export const sameIdentifier = (left: LoginIdentifier, right: LoginIdentifier) =>
  left.namespace === right.namespace && left.value === right.value;

export const validEmailSignInConstraints = (mapping: SignInMapping) =>
  Object.entries(requiredEmailSignInConstraints).every(
    ([key, value]) =>
      mapping.constraints[key as keyof typeof requiredEmailSignInConstraints] === value,
  );

export const validAddressConstraints = (mapping: AddressMapping) =>
  Object.entries(requiredEmailAddressConstraints).every(
    ([key, value]) =>
      mapping.constraints[key as keyof typeof requiredEmailAddressConstraints] === value,
  );

export const subjectColumns = (mapping: SignInMapping) => ({
  id: column(mapping.subject.table, mapping.subject.id),
  status: column(mapping.subject.table, mapping.subject.status),
  securityRevision: column(mapping.subject.table, mapping.subject.securityRevision),
});

export const identifierColumns = (mapping: SignInMapping) => ({
  namespace: column(mapping.identifier.table, mapping.identifier.namespace),
  value: column(mapping.identifier.table, mapping.identifier.value),
  subjectId: column(mapping.identifier.table, mapping.identifier.subjectId),
  verifiedAt: column(mapping.identifier.table, mapping.identifier.verifiedAt),
  bindingRevision: column(mapping.identifier.table, mapping.identifier.bindingRevision),
});

export const credentialColumns = (mapping: SignInMapping) => ({
  moduleId: column(mapping.credential.table, mapping.credential.moduleId),
  subjectId: column(mapping.credential.table, mapping.credential.subjectId),
  credentialId: column(mapping.credential.table, mapping.credential.credentialId),
  identifierNamespace: column(mapping.credential.table, mapping.credential.identifierNamespace),
  identifierValue: column(mapping.credential.table, mapping.credential.identifierValue),
  credentialRevision: column(mapping.credential.table, mapping.credential.credentialRevision),
  status: column(mapping.credential.table, mapping.credential.status),
});

export const authorityColumns = (mapping: AddressMapping) => ({
  subjectId: column(mapping.authorityCredential.table, mapping.authorityCredential.subjectId),
  credentialId: column(mapping.authorityCredential.table, mapping.authorityCredential.credentialId),
  revision: column(mapping.authorityCredential.table, mapping.authorityCredential.revision),
  status: column(mapping.authorityCredential.table, mapping.authorityCredential.status),
});

export const commandColumns = (mapping: AddressMapping) => ({
  moduleId: column(mapping.command.table, mapping.command.moduleId),
  commandId: column(mapping.command.table, mapping.command.commandId),
  action: column(mapping.command.table, mapping.command.action),
  bindingDigest: column(mapping.command.table, mapping.command.bindingDigest),
  retentionUntil: column(mapping.command.table, mapping.command.retentionUntil),
});

export const safeRead = <A, E, R>(
  database: NativeSqlDatabase,
  configuration: EmailSqlConfiguration,
  body: Effect.Effect<A, E, R>,
  advisorySnapshot = false,
) =>
  Effect.gen(function* () {
    if (configuration.coordinated !== true) {
      if (yield* hasCommitScope) return yield* unavailable();
      yield* configuration.standaloneGuard;
    }

    const run = (transaction: NativeSqlDatabase) =>
      body.pipe(
        Effect.provideService(CurrentEmailSql, transaction),
        Effect.provideService(CurrentProofSql, transaction),
      );

    return yield* advisorySnapshot ? run(database) : database.transaction(run);
  });

export const emailLookupQuery = (
  mapping: SignInMapping,
  moduleId: string,
  identifier: LoginIdentifier,
) => {
  const subject = subjectColumns(mapping),
    binding = identifierColumns(mapping),
    credential = credentialColumns(mapping);

  return {
    fields: {
      subject: mapping.subject.table,
      identifier: mapping.identifier.table,
      credential: mapping.credential.table,
    },
    from: mapping.identifier.table,
    subjectTable: mapping.subject.table,
    subjectJoin: eq(subject.id, binding.subjectId),
    credentialTable: mapping.credential.table,
    credentialJoin: and(
      eq(credential.moduleId, moduleId),
      eq(credential.subjectId, binding.subjectId),
      eq(credential.identifierNamespace, binding.namespace),
      eq(credential.identifierValue, binding.value),
    ),
    predicate: and(
      eq(binding.namespace, identifier.namespace),
      eq(binding.value, identifier.value),
    ),
    limit: 1,
  };
};

export const emailLookupRows = Effect.fn("Drizzle.emailLookupRows")(function* (
  mapping: SignInMapping,
  moduleId: string,
  identifier: LoginIdentifier,
) {
  const database = yield* CurrentEmailSql;
  const query = emailLookupQuery(mapping, moduleId, identifier);

  return yield* database
    .select(query.fields)
    .from(query.from)
    .innerJoin(query.subjectTable, query.subjectJoin)
    .innerJoin(query.credentialTable, query.credentialJoin)
    .where(query.predicate)
    .limit(query.limit);
});

export const decodeEmailSnapshot = Effect.fn("DrizzleEmail.decodeSnapshot")(function* (
  mapping: SignInMapping,
  moduleId: string,
  requested: LoginIdentifier,
  row: any,
) {
  if (
    !mapping.subject.isActiveStatus(row.subject[mapping.subject.status]) ||
    !mapping.identifier.isCurrent(row.identifier) ||
    !mapping.credential.isActiveStatus(row.credential[mapping.credential.status])
  )
    return undefined;

  const snapshot = yield* mapping.credential
    .decode({
      moduleId,
      subject: row.subject,
      identifier: row.identifier,
      credential: row.credential,
    })
    .pipe(Effect.flatMap(snapshotEmailCredential));

  const subjectId = yield* mapping.subjectId.toSubject(row.subject[mapping.subject.id]);

  const verifiedAtMillis = yield* mapping.decodeInstant(
    row.identifier[mapping.identifier.verifiedAt],
  );

  if (
    snapshot.moduleId !== moduleId ||
    !sameIdentifier(snapshot.identifier, requested) ||
    snapshot.revision.subjectId !== subjectId ||
    snapshot.revision.securityRevision !== row.subject[mapping.subject.securityRevision] ||
    snapshot.identifierRevision !== row.identifier[mapping.identifier.bindingRevision] ||
    snapshot.verifiedAtMillis !== verifiedAtMillis ||
    snapshot.credentialId !== row.credential[mapping.credential.credentialId] ||
    snapshot.credentialRevision !== row.credential[mapping.credential.credentialRevision]
  )
    return undefined;

  return snapshot;
});

export const readSubject = Effect.fn("DrizzleEmail.readSubject")(function* (
  mapping: AddressMapping,
  subjectId: string,
  locking: boolean,
) {
  const database = yield* CurrentEmailSql;

  const nativeSubjectId = yield* mapping.subjectId.toNative(subjectId as any);
  const s = subjectColumns(mapping);

  const subject = (yield* selectRows(
    database.select().from(mapping.subject.table).where(eq(s.id, nativeSubjectId)).limit(1),
    locking,
  ))[0];

  return { nativeSubjectId, subject };
});

export const credentialById = Effect.fn("Drizzle.credentialById")(function* (
  mapping: SignInMapping,
  moduleId: string,
  credentialId: string,
  locking: boolean,
) {
  const database = yield* CurrentEmailSql;

  const c = credentialColumns(mapping);

  return yield* selectRows(
    database
      .select()
      .from(mapping.credential.table)
      .where(and(eq(c.moduleId, moduleId), eq(c.credentialId, credentialId)))
      .limit(1),
    locking,
  );
});

export const readRows = Effect.fnUntraced(function* (
  database: NativeSqlDatabase,
  reads: ReadonlyArray<SnapshotRead>,
  locking: boolean,
  configuration: Pick<EmailSqlConfiguration, "maxParameters" | "pgOrderedLocks">,
  advisorySnapshot = false,
) {
  if (!locking || configuration.pgOrderedLocks) {
    const snapshot = readSnapshots(
      database,
      reads,
      configuration.maxParameters,
      locking && configuration.pgOrderedLocks,
    );

    return yield* advisorySnapshot && !snapshot.singleStatement
      ? database.transaction(
          (transaction) => readSnapshots(transaction, reads, configuration.maxParameters).rows,
        )
      : snapshot.rows;
  }

  return yield* Effect.forEach(reads, (read) => {
    let query = database.select().from(read.table).where(read.where);

    if (read.limit !== undefined) query = query.limit(read.limit);
    if (read.orderBy !== undefined) query = query.orderBy(...read.orderBy);

    return selectRows(query, locking);
  });
});

export const authorityReads = (
  mapping: AddressMapping,
  nativeSubjectId: unknown,
): readonly [SnapshotRead, SnapshotRead] => {
  const s = subjectColumns(mapping);
  const a = authorityColumns(mapping);

  return [
    { table: mapping.subject.table, where: eq(s.id, nativeSubjectId), limit: 1 },
    {
      table: mapping.authorityCredential.table,
      where: eq(a.subjectId, nativeSubjectId),
      orderBy: [a.credentialId],
    },
  ];
};

export const addressRevision = Effect.fnUntraced(function* (
  mapping: AddressMapping,
  nativeSubjectId: unknown,
  subject: any,
  authority: ReadonlyArray<Record<string, any>>,
) {
  if (subject === undefined || !mapping.subject.isActiveStatus(subject[mapping.subject.status]))
    return undefined;
  const subjectId = yield* mapping.subjectId.toSubject(nativeSubjectId);

  return Object.freeze({
    subjectId,
    securityRevision: subject[mapping.subject.securityRevision],
    credentials: Object.freeze(
      authority
        .filter((row) =>
          mapping.authorityCredential.isActiveStatus(row[mapping.authorityCredential.status]),
        )
        .map((row) =>
          Object.freeze({
            credentialId: row[mapping.authorityCredential.credentialId],
            revision: row[mapping.authorityCredential.revision],
          }),
        ),
    ),
  });
});

export const addressRead = Effect.fnUntraced(function* (
  mapping: AddressMapping,
  input: {
    readonly moduleId: string;
    readonly subjectId: string;
    readonly target: LoginIdentifier;
    readonly sourceCredentialId?: string;
  },
  discovery?: {
    readonly nativeSubjectId: unknown;
    readonly subject: any;
    readonly identifier: LoginIdentifier | undefined;
  },
) {
  const nativeSubjectId =
    discovery === undefined
      ? yield* mapping.subjectId.toNative(input.subjectId as any)
      : discovery.nativeSubjectId;

  const [subjectRead, authorityRead] = authorityReads(mapping, nativeSubjectId);
  const sourceIdentifier = discovery?.identifier;
  const i = identifierColumns(mapping);
  const c = credentialColumns(mapping);
  const reads: SnapshotRead[] = [];
  const add = (read: SnapshotRead) => reads.push(read) - 1;
  const subjectIndex = discovery === undefined ? add(subjectRead) : undefined;

  const identifiers = [input.target, ...(sourceIdentifier === undefined ? [] : [sourceIdentifier])]
    .filter(
      (value, index, values) =>
        values.findIndex((candidate) => sameIdentifier(candidate, value)) === index,
    )
    .sort((left, right) =>
      `${left.namespace}\u0000${left.value}`.localeCompare(
        `${right.namespace}\u0000${right.value}`,
      ),
    );

  const identifierIndexes = identifiers.map((identifier) =>
    add({
      table: mapping.identifier.table,
      where: and(eq(i.namespace, identifier.namespace), eq(i.value, identifier.value)),
      limit: 1,
    }),
  );

  const sourceIndex =
    input.sourceCredentialId === undefined
      ? undefined
      : add({
          table: mapping.credential.table,
          where: and(eq(c.moduleId, input.moduleId), eq(c.credentialId, input.sourceCredentialId)),
          limit: 1,
        });

  const targetIndex = add({
    table: mapping.credential.table,
    where: and(
      eq(c.moduleId, input.moduleId),
      eq(c.identifierNamespace, input.target.namespace),
      eq(c.identifierValue, input.target.value),
    ),
    limit: 1,
  });

  const authorityIndex = add(authorityRead);

  const cardinalityIndex =
    mapping.addressCardinality === "single" && input.sourceCredentialId === undefined
      ? add({
          table: mapping.credential.table,
          where: and(eq(c.moduleId, input.moduleId), eq(c.subjectId, nativeSubjectId)),
        })
      : undefined;

  return {
    reads,
    current: Effect.fnUntraced(function* (rows: ReadonlyArray<ReadonlyArray<Record<string, any>>>) {
      const subject = discovery === undefined ? rows[subjectIndex!]![0] : discovery.subject;

      const revision = yield* addressRevision(
        mapping,
        nativeSubjectId,
        subject,
        rows[authorityIndex]!,
      );

      if (revision === undefined) return undefined;
      const lockedIdentifiers = new Map<string, any>();

      for (const [index, identifier] of identifiers.entries()) {
        const row = rows[identifierIndexes[index]!]![0];

        if (row !== undefined)
          lockedIdentifiers.set(`${identifier.namespace}\u0000${identifier.value}`, row);
      }
      const sourceCredential = sourceIndex === undefined ? undefined : rows[sourceIndex]![0];
      const targetCredential = rows[targetIndex]![0];

      const targetIdentifier = lockedIdentifiers.get(
        `${input.target.namespace}\u0000${input.target.value}`,
      );

      const targetOwned =
        targetIdentifier !== undefined &&
        mapping.subjectId.equals(targetIdentifier[mapping.identifier.subjectId], nativeSubjectId);

      const targetMutable =
        targetOwned &&
        mapping.identifier.isMutableTarget(targetIdentifier) &&
        (targetCredential === undefined ||
          (!mapping.credential.isActiveStatus(targetCredential[mapping.credential.status]) &&
            mapping.subjectId.equals(
              targetCredential[mapping.credential.subjectId],
              nativeSubjectId,
            )));

      let source: CurrentAddress["source"];

      if (input.sourceCredentialId !== undefined) {
        if (
          sourceCredential === undefined ||
          sourceIdentifier === undefined ||
          !mapping.subjectId.equals(
            sourceCredential[mapping.credential.subjectId],
            nativeSubjectId,
          ) ||
          !mapping.credential.isActiveStatus(sourceCredential[mapping.credential.status])
        )
          return undefined;

        const sourceIdentifierRow = lockedIdentifiers.get(
          `${sourceIdentifier.namespace}\u0000${sourceIdentifier.value}`,
        );

        if (
          sourceIdentifierRow === undefined ||
          !mapping.identifier.isCurrent(sourceIdentifierRow) ||
          !mapping.subjectId.equals(
            sourceIdentifierRow[mapping.identifier.subjectId],
            nativeSubjectId,
          )
        )
          return undefined;

        const snapshot = yield* mapping.credential
          .decode({
            moduleId: input.moduleId,
            subject,
            identifier: sourceIdentifierRow,
            credential: sourceCredential,
          })
          .pipe(Effect.flatMap(snapshotEmailCredential));

        source = { credential: sourceCredential, identifier: sourceIdentifierRow, snapshot };
      }

      let eligible =
        targetIdentifier === undefined ? targetCredential === undefined : targetMutable;

      if (input.sourceCredentialId !== undefined && source === undefined) eligible = false;
      if (source !== undefined && sameIdentifier(source.snapshot.identifier, input.target))
        eligible = false;
      if (
        cardinalityIndex !== undefined &&
        rows[cardinalityIndex]!.some((row) =>
          mapping.credential.isActiveStatus(row[mapping.credential.status]),
        )
      )
        eligible = false;

      return {
        nativeSubjectId,
        subject,
        revision,
        ...(source === undefined ? {} : { source }),
        ...(targetIdentifier === undefined ? {} : { targetIdentifier }),
        ...(targetCredential === undefined ? {} : { targetCredential }),
        ...(targetMutable
          ? { targetIdentifierRevision: targetIdentifier[mapping.identifier.bindingRevision] }
          : {}),
        eligible,
      };
    }),
  };
});

export const currentAddress = Effect.fn("DrizzleEmail.currentAddress")(function* (
  mapping: AddressMapping,
  input: Parameters<typeof addressRead>[1],
  locking: boolean,
  configuration: Pick<EmailSqlConfiguration, "maxParameters" | "pgOrderedLocks"> = {},
  advisorySnapshot = false,
) {
  const database = yield* CurrentEmailSql;
  let discovery: Parameters<typeof addressRead>[2];

  if (input.sourceCredentialId !== undefined) {
    const locked = yield* readSubject(mapping, input.subjectId, locking);

    if (
      locked.subject === undefined ||
      !mapping.subject.isActiveStatus(locked.subject[mapping.subject.status])
    )
      return undefined;

    const source = (yield* credentialById(
      mapping,
      input.moduleId,
      input.sourceCredentialId,
      false,
    ))[0];

    // Decode the source before binding its identifier through the destination
    // columns. A raw SQL join would bypass custom decoder/encoder semantics.
    discovery = {
      ...locked,
      identifier:
        source === undefined
          ? undefined
          : {
              namespace: source[mapping.credential.identifierNamespace],
              value: source[mapping.credential.identifierValue],
            },
    };
  }
  const read = yield* addressRead(mapping, input, discovery);

  return yield* read.current(
    yield* readRows(database, read.reads, locking, configuration, advisorySnapshot),
  );
});

export const addressTarget = Effect.fnUntraced(function* (current: CurrentAddress) {
  return Object.freeze({
    revision: snapshotEmailRevision(current.revision),
    eligible: current.eligible,
    ...(current.targetIdentifierRevision === undefined
      ? {}
      : { targetIdentifierRevision: current.targetIdentifierRevision }),
    ...(current.source === undefined
      ? {}
      : { source: yield* snapshotEmailCredential(current.source.snapshot) }),
  });
});

/** The staged and interactive writers share the same semantic authorization decision. */
export const validateEmailAuthority = Effect.fn("DrizzleEmail.validateAuthority")(function* (
  mapping: AddressMapping,
  configuration: EmailSqlConfiguration,
  input: EmailAddressMutation,
  action: EmailAction,
) {
  const current = yield* currentAddress(
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

  const valid = yield* validateEmailMutation(mapping, input, action, {
    target: yield* addressTarget(current),
    requirement: mapping.subject.decodeActionRequirement(current.subject, action),
  });

  return valid ? current : undefined;
});

export const commandExists = Effect.fn("Drizzle.commandExists")(function* (
  mapping: AddressMapping,
  moduleId: string,
  commandId: string,
  locking: boolean,
) {
  const database = yield* CurrentEmailSql;

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

export const applyMutation = Effect.fn("DrizzleEmail.applyMutation")(function* (
  mapping: AddressMapping,
  input: EmailAddressMutation,
  action: EmailAction,
  current: CurrentAddress,
  allocated: {
    readonly targetCredentialId: string;
    readonly targetIdentifierRevision: SecurityRevision;
    readonly targetCredentialRevision: SecurityRevision;
    readonly sourceIdentifierRevision: SecurityRevision;
    readonly sourceCredentialRevision: SecurityRevision;
    readonly nextSecurityRevision: SecurityRevision;
  },
  now: number,
) {
  const database = yield* CurrentEmailSql;

  const i = identifierColumns(mapping);
  const c = credentialColumns(mapping);
  const a = authorityColumns(mapping);
  const s = subjectColumns(mapping);

  const targetCredentialId = yield* Schema.decodeUnknownEffect(Schema.String)(
    current.targetCredential?.[mapping.credential.credentialId] ?? allocated.targetCredentialId,
  );

  if (action === "change-address") {
    const source = current.source!;

    yield* database
      .update(mapping.identifier.table)
      .set(
        mapping.identifier.encodeRetirement({
          source: source.snapshot.identifier,
          bindingRevision: allocated.sourceIdentifierRevision,
        }),
      )
      .where(
        and(
          eq(i.namespace, source.snapshot.identifier.namespace),
          eq(i.value, source.snapshot.identifier.value),
          eq(i.subjectId, current.nativeSubjectId),
          eq(i.bindingRevision, source.snapshot.identifierRevision),
        ),
      );
    yield* database
      .update(mapping.credential.table)
      .set(
        mapping.credential.encodeRetirement({
          source: source.snapshot.identifier,
          credentialRevision: allocated.sourceCredentialRevision,
        }),
      )
      .where(
        and(
          eq(c.moduleId, input.moduleId),
          eq(c.credentialId, source.snapshot.credentialId),
          eq(c.subjectId, current.nativeSubjectId),
          eq(c.credentialRevision, source.snapshot.credentialRevision),
        ),
      );
    yield* database
      .update(mapping.authorityCredential.table)
      .set(mapping.authorityCredential.encodeRetirement(allocated.sourceCredentialRevision))
      .where(
        and(
          eq(a.subjectId, current.nativeSubjectId),
          eq(a.credentialId, source.snapshot.credentialId),
          eq(a.revision, source.snapshot.credentialRevision),
        ),
      );
  }
  if (current.targetIdentifier === undefined) {
    yield* database.insert(mapping.identifier.table).values(
      mapping.identifier.encodeVerifiedInsert({
        identifier: input.target,
        subjectId: current.nativeSubjectId,
        verifiedAtMillis: now,
        bindingRevision: allocated.targetIdentifierRevision,
      }),
    );
  } else {
    yield* database
      .update(mapping.identifier.table)
      .set(
        mapping.identifier.encodeVerification({
          verifiedAtMillis: now,
          bindingRevision: allocated.targetIdentifierRevision,
        }),
      )
      .where(
        and(
          eq(i.namespace, input.target.namespace),
          eq(i.value, input.target.value),
          eq(i.subjectId, current.nativeSubjectId),
          eq(i.bindingRevision, current.targetIdentifier![mapping.identifier.bindingRevision]),
        ),
      );
  }
  if (current.targetCredential === undefined) {
    yield* database.insert(mapping.credential.table).values(
      mapping.credential.encodeVerifiedInsert({
        moduleId: input.moduleId,
        subjectId: current.nativeSubjectId,
        credentialId: targetCredentialId,
        identifier: input.target,
        credentialRevision: allocated.targetCredentialRevision,
      }),
    );
    yield* database.insert(mapping.authorityCredential.table).values(
      mapping.authorityCredential.encodeInsert({
        subjectId: current.nativeSubjectId,
        credentialId: targetCredentialId,
        revision: allocated.targetCredentialRevision,
      }),
    );
  } else {
    const oldRevision = current.targetCredential[mapping.credential.credentialRevision];

    yield* database
      .update(mapping.credential.table)
      .set(
        mapping.credential.encodeActivation({
          identifier: input.target,
          credentialRevision: allocated.targetCredentialRevision,
        }),
      )
      .where(
        and(
          eq(c.moduleId, input.moduleId),
          eq(c.credentialId, targetCredentialId),
          eq(c.subjectId, current.nativeSubjectId),
          eq(c.credentialRevision, oldRevision),
        ),
      );
    yield* database
      .update(mapping.authorityCredential.table)
      .set(mapping.authorityCredential.encodeActivation(allocated.targetCredentialRevision))
      .where(
        and(
          eq(a.subjectId, current.nativeSubjectId),
          eq(a.credentialId, targetCredentialId),
          eq(a.revision, oldRevision),
        ),
      );
  }
  yield* database
    .update(mapping.subject.table)
    .set(updateValues([[mapping.subject.securityRevision, allocated.nextSecurityRevision]]))
    .where(
      and(
        eq(s.id, current.nativeSubjectId),
        eq(s.securityRevision, input.captured.revision.securityRevision),
      ),
    );
  yield* database.insert(mapping.command.table).values(
    mapping.command.encodeInsert({
      moduleId: input.moduleId,
      commandId: input.commandId,
      action,
      bindingDigest: input.authorization.challenge.bindingDigest,
      retentionUntilMillis: now + mapping.commandRetentionMillis,
    }),
  );

  // Read both authority rows together, retaining the database's key comparison
  // semantics even when a custom mapping uses a non-binary collation.
  const targetAuthorityCondition = and(
    eq(a.subjectId, current.nativeSubjectId),
    eq(a.credentialId, targetCredentialId),
  );

  const sourceCredentialId = current.source?.snapshot.credentialId;

  const sourceAuthorityCondition =
    sourceCredentialId === undefined
      ? sql`1 = 0`
      : and(eq(a.subjectId, current.nativeSubjectId), eq(a.credentialId, sourceCredentialId));

  const command = commandColumns(mapping);

  const commandCondition = and(
    eq(command.moduleId, input.moduleId),
    eq(command.commandId, input.commandId),
    eq(command.action, action),
    eq(command.bindingDigest, input.authorization.challenge.bindingDigest),
    eq(command.retentionUntil, mapping.encodeInstant(now + mapping.commandRetentionMillis)),
  );

  const source =
    action === "verify-address"
      ? []
      : yield* database
          .select({ credential: mapping.credential.table, identifier: mapping.identifier.table })
          .from(mapping.credential.table)
          .innerJoin(
            mapping.identifier.table,
            and(
              eq(i.namespace, current.source!.snapshot.identifier.namespace),
              eq(i.value, current.source!.snapshot.identifier.value),
            ),
          )
          .where(
            and(
              eq(c.moduleId, input.moduleId),
              eq(c.credentialId, sourceCredentialId),
              eq(c.subjectId, current.nativeSubjectId),
            ),
          );

  const target = (yield* emailLookupRows(mapping, input.moduleId, input.target))[0];

  const authority = yield* database
    .select({
      row: mapping.authorityCredential.table,
      target: sql`case when ${targetAuthorityCondition} then 1 else 0 end`.mapWith(Number),
      source: sql`case when ${sourceAuthorityCondition} then 1 else 0 end`.mapWith(Number),
      command:
        sql`case when exists(select 1 from ${mapping.command.table} where ${commandCondition}) then 1 else 0 end`.mapWith(
          Number,
        ),
    })
    .from(mapping.authorityCredential.table)
    .where(
      and(
        eq(a.subjectId, current.nativeSubjectId),
        inArray(
          a.credentialId,
          sourceCredentialId === undefined
            ? [targetCredentialId]
            : [targetCredentialId, sourceCredentialId],
        ),
      ),
    );

  const targetAuthority = authority.filter((entry: any) => entry.target === 1);
  const sourceAuthority = authority.filter((entry: any) => entry.source === 1);

  const targetVerifiedAt =
    target === undefined
      ? undefined
      : yield* mapping.decodeInstant(target.identifier[mapping.identifier.verifiedAt]);

  return (
    target !== undefined &&
    mapping.subjectId.equals(target.subject[mapping.subject.id], current.nativeSubjectId) &&
    mapping.subject.isActiveStatus(target.subject[mapping.subject.status]) &&
    target.subject[mapping.subject.securityRevision] === allocated.nextSecurityRevision &&
    target.identifier[mapping.identifier.bindingRevision] === allocated.targetIdentifierRevision &&
    targetVerifiedAt === now &&
    target.credential[mapping.credential.credentialRevision] ===
      allocated.targetCredentialRevision &&
    target.credential[mapping.credential.credentialId] === targetCredentialId &&
    mapping.subjectId.equals(
      target.credential[mapping.credential.subjectId],
      current.nativeSubjectId,
    ) &&
    mapping.identifier.isCurrent(target.identifier) &&
    mapping.credential.isActiveStatus(target.credential[mapping.credential.status]) &&
    targetAuthority.length === 1 &&
    targetAuthority[0]!.row[mapping.authorityCredential.revision] ===
      allocated.targetCredentialRevision &&
    mapping.authorityCredential.isActiveStatus(
      targetAuthority[0]!.row[mapping.authorityCredential.status],
    ) &&
    targetAuthority[0]!.command === 1 &&
    (action === "verify-address" ||
      (source.length === 1 &&
        source[0]!.credential[mapping.credential.credentialRevision] ===
          allocated.sourceCredentialRevision &&
        !mapping.credential.isActiveStatus(source[0]!.credential[mapping.credential.status]) &&
        mapping.subjectId.equals(
          source[0]!.identifier[mapping.identifier.subjectId],
          current.nativeSubjectId,
        ) &&
        source[0]!.identifier[mapping.identifier.bindingRevision] ===
          allocated.sourceIdentifierRevision &&
        !mapping.identifier.isCurrent(source[0]!.identifier) &&
        sourceAuthority.length === 1 &&
        sourceAuthority[0]!.row[mapping.authorityCredential.revision] ===
          allocated.sourceCredentialRevision &&
        !mapping.authorityCredential.isActiveStatus(
          sourceAuthority[0]!.row[mapping.authorityCredential.status],
        )))
  );
});
