import {
  type AnyPasswordPersistenceMapping,
  requiredPasswordConstraints,
  validatePasswordMutation,
} from "@yielded/auth-persistence/Adapter";
import { coordinateCommit, hasCommitScope, HookConfigurationError } from "@yielded/auth/Hooks";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import {
  PasswordUnavailable,
  type PasswordMutationInput,
  snapshotPasswordCredential,
  type PasswordAction,
} from "@yielded/auth/Password";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import { SecurityRevision } from "@yielded/auth/Sessions";
/* oxlint-disable no-explicit-any -- existing storage kernels erase foreign table shapes; domain errors remain typed. */
import { and, eq, inArray } from "drizzle-orm";
import { Cause, DateTime, Effect, Redacted, Schema } from "effect";

import { column, updateValues } from "./model";
import type { NativeSqlDatabase, NativeSqlQuery } from "./native-database";
import { CurrentPasswordSql, type PasswordSqlConfiguration } from "./password-database";
import { CurrentProofSql } from "./proof-database";
import { readSnapshot as readSnapshots, type SnapshotRead } from "./sql-snapshot";

type Mapping = AnyPasswordPersistenceMapping;
type Database = NativeSqlDatabase;
export const unavailable = () => PasswordUnavailable.make({});

export const translateFailure = <A, E, R>(
  effect: Effect.Effect<A, E, R>,
): Effect.Effect<A, PasswordUnavailable, R> =>
  reportPersistenceFailure(
    effect,
    (error) =>
      Schema.is(PasswordUnavailable)(error) ||
      Schema.is(ProofUnavailable)(error) ||
      Schema.is(HookConfigurationError)(error),
  ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, () => unavailable()))));

export const nowMillis = DateTime.now.pipe(Effect.map(DateTime.toEpochMillis));

export const validConstraints = (mapping: Mapping) =>
  Object.entries(requiredPasswordConstraints).every(
    ([key, value]) =>
      mapping.constraints[key as keyof typeof requiredPasswordConstraints] === value,
  );

export const selectRows = (query: NativeSqlQuery, locking: boolean) =>
  locking && typeof query.for === "function" ? query.for("update") : query;

export const subjectColumns = (mapping: Mapping) => ({
  id: column(mapping.subject.table, mapping.subject.id),
  status: column(mapping.subject.table, mapping.subject.status),
  securityRevision: column(mapping.subject.table, mapping.subject.securityRevision),
});

export const identifierColumns = (mapping: Mapping) => ({
  namespace: column(mapping.identifier.table, mapping.identifier.namespace),
  value: column(mapping.identifier.table, mapping.identifier.value),
  subjectId: column(mapping.identifier.table, mapping.identifier.subjectId),
  verifiedAt: column(mapping.identifier.table, mapping.identifier.verifiedAt),
  bindingRevision: column(mapping.identifier.table, mapping.identifier.bindingRevision),
});

export const credentialColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.credential.table, mapping.credential.moduleId),
  subjectId: column(mapping.credential.table, mapping.credential.subjectId),
  credentialId: column(mapping.credential.table, mapping.credential.credentialId),
  credentialRevision: column(mapping.credential.table, mapping.credential.credentialRevision),
  verifierVersion: column(mapping.credential.table, mapping.credential.verifierVersion),
  verifier: column(mapping.credential.table, mapping.credential.verifier),
  normalization: column(mapping.credential.table, mapping.credential.normalization),
});

export const authorityCredentialColumns = (mapping: Mapping) => ({
  subjectId: column(mapping.authorityCredential.table, mapping.authorityCredential.subjectId),
  credentialId: column(mapping.authorityCredential.table, mapping.authorityCredential.credentialId),
  revision: column(mapping.authorityCredential.table, mapping.authorityCredential.revision),
});

export const commandColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.command.table, mapping.command.moduleId),
  commandId: column(mapping.command.table, mapping.command.commandId),
  action: column(mapping.command.table, mapping.command.action),
  bindingDigest: column(mapping.command.table, mapping.command.bindingDigest),
  decision: column(mapping.command.table, mapping.command.decision),
  retentionUntil: column(mapping.command.table, mapping.command.retentionUntil),
});

export const lockSubject = Effect.fn("DrizzlePassword.lockSubject")(function* (
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

export const lockIdentifier = Effect.fn("Drizzle.lockIdentifier")(function* (
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

export const readPasswordCredential = Effect.fn("Drizzle.readPasswordCredential")(function* (
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

type SnapshotRows = ReadonlyArray<ReadonlyArray<Record<string, any>>>;

export const readRows = Effect.fnUntraced(function* (
  database: Database,
  reads: ReadonlyArray<SnapshotRead>,
  locking: boolean,
  maxParameters?: number,
  pgOrderedLocks = false,
  advisory = false,
) {
  if (!locking || pgOrderedLocks) {
    const snapshot = readSnapshots(database, reads, maxParameters, pgOrderedLocks);

    return yield* advisory && !snapshot.singleStatement
      ? database.transaction((transaction) => readSnapshots(transaction, reads, maxParameters).rows)
      : snapshot.rows;
  }

  return yield* Effect.forEach(reads, (read) => {
    let query = database.select().from(read.table).where(read.where);

    if (read.limit !== undefined) query = query.limit(read.limit);
    if (read.orderBy !== undefined) query = query.orderBy(...read.orderBy);

    return selectRows(query, locking);
  });
});

export const credentialRead = (
  mapping: Mapping,
  moduleId: string,
  identifier: LoginIdentifier,
  nativeSubjectId: unknown,
  requestedSubjectId?: string,
) => {
  const s = subjectColumns(mapping),
    i = identifierColumns(mapping),
    c = credentialColumns(mapping);

  const reads: ReadonlyArray<SnapshotRead> = [
    { table: mapping.subject.table, where: eq(s.id, nativeSubjectId), limit: 1 },
    {
      table: mapping.identifier.table,
      where: and(eq(i.namespace, identifier.namespace), eq(i.value, identifier.value)),
      limit: 1,
    },
    {
      table: mapping.credential.table,
      where: and(eq(c.moduleId, moduleId), eq(c.subjectId, nativeSubjectId)),
      limit: 1,
    },
  ];

  return {
    reads,
    current: Effect.fnUntraced(function* (rows: SnapshotRows) {
      const subject = rows[0]?.[0];

      if (subject === undefined || !mapping.subject.isActiveStatus(subject[mapping.subject.status]))
        return undefined;
      const identifierRow = rows[1]?.[0];

      if (
        identifierRow === undefined ||
        !mapping.identifier.isCurrent(identifierRow) ||
        !mapping.subjectId.equals(nativeSubjectId, identifierRow[mapping.identifier.subjectId])
      )
        return undefined;
      const subjectId = yield* mapping.subjectId.toSubject(nativeSubjectId);

      if (requestedSubjectId !== undefined && requestedSubjectId !== subjectId) return undefined;
      const credential = rows[2]?.[0];

      if (credential === undefined) return { nativeSubjectId, subject, identifier: identifierRow };

      const decoded = yield* mapping.credential
        .decode({ moduleId, subject, identifier: identifierRow, credential })
        .pipe(Effect.flatMap(snapshotPasswordCredential));

      return {
        nativeSubjectId,
        subject,
        identifier: identifierRow,
        credential,
        snapshot: decoded,
      };
    }),
  };
};

export const resolveCredential = Effect.fn("DrizzlePassword.resolveCredential")(function* (
  mapping: Mapping,
  moduleId: string,
  identifier: LoginIdentifier,
  requestedSubjectId: string | undefined,
  locking: boolean,
  advisory = false,
  maxParameters?: number,
  pgOrderedLocks = false,
) {
  const database = yield* CurrentPasswordSql;
  // Discovery supplies only the native key. The later snapshot checks ownership.
  let nativeSubjectId: unknown;

  if (requestedSubjectId === undefined) {
    const discovered = (yield* lockIdentifier(mapping, identifier, false))[0];

    if (discovered === undefined || !mapping.identifier.isCurrent(discovered)) return undefined;
    nativeSubjectId = discovered[mapping.identifier.subjectId];
  } else {
    nativeSubjectId = yield* mapping.subjectId.toNative(requestedSubjectId as any);
  }
  const read = credentialRead(mapping, moduleId, identifier, nativeSubjectId, requestedSubjectId);

  return yield* read.current(
    yield* readRows(database, read.reads, locking, maxParameters, pgOrderedLocks, advisory),
  );
});

export const owned = <A, E, R>(
  database: Database,
  mapping: Mapping,
  configuration: PasswordSqlConfiguration,
  body: Effect.Effect<A, E, R>,
) => {
  if (!validConstraints(mapping)) return Effect.fail(unavailable());

  const run = coordinateCommit(() =>
    database.transaction((transaction) =>
      body.pipe(
        Effect.provideService(CurrentPasswordSql, transaction),
        Effect.provideService(CurrentProofSql, transaction),
      ),
    ),
  ).pipe(Effect.map((result) => result.value));

  return configuration.coordinated !== true
    ? Effect.gen(function* () {
        if (yield* hasCommitScope) return yield* unavailable();
        yield* configuration.standaloneGuard;

        return yield* run;
      })
    : run;
};

export const safeRead = <A, E, R>(
  database: Database,
  configuration: PasswordSqlConfiguration,
  body: Effect.Effect<A, E, R>,
  advisorySnapshot = false,
) =>
  Effect.gen(function* () {
    if (configuration.coordinated !== true) {
      if (yield* hasCommitScope) return yield* unavailable();
      yield* configuration.standaloneGuard;
    }

    const run = (transaction: Database) =>
      body.pipe(
        Effect.provideService(CurrentPasswordSql, transaction),
        Effect.provideService(CurrentProofSql, transaction),
      );

    // Only explicitly captured advisory snapshots may omit transaction calls.
    return yield* advisorySnapshot ? run(database) : database.transaction(run);
  });

/** Native authority reads; shared policy decides whether these facts authorize a change. */
export const readMutationAuthority = Effect.fn("DrizzlePassword.readMutationAuthority")(function* (
  mapping: Mapping,
  configuration: PasswordSqlConfiguration,
  input: PasswordMutationInput,
  action: PasswordAction,
  captured?: {
    readonly nativeSubjectId: unknown;
    readonly subject: Record<string, any> | undefined;
    readonly identifier: Record<string, any> | undefined;
    readonly credentials: ReadonlyArray<Record<string, any>>;
    readonly password: Record<string, any> | undefined;
  },
) {
  const database = yield* CurrentPasswordSql;

  const locked =
    captured === undefined
      ? yield* lockSubject(mapping, input.expectedRevision.subjectId, configuration.locking)
      : { nativeSubjectId: captured.nativeSubjectId, row: captured.subject };

  const row = locked.row;

  const identifier =
    captured !== undefined
      ? captured.identifier
      : input.credential === undefined
        ? undefined
        : (yield* lockIdentifier(mapping, input.credential.identifier, configuration.locking))[0];

  const expected = new Map(
    [
      ...input.expectedRevision.credentials,
      ...input.authorization.evidence.revision.credentials,
    ].map((item) => [item.credentialId, item]),
  );

  const ac = authorityCredentialColumns(mapping);

  const credentials =
    captured !== undefined
      ? captured.credentials
      : expected.size === 0
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

  const credential =
    captured !== undefined
      ? captured.password
      : input.credential === undefined
        ? undefined
        : (yield* readPasswordCredential(
            mapping,
            input.moduleId,
            locked.nativeSubjectId,
            configuration.locking,
          ))[0];

  const facts = {
    subject:
      row === undefined
        ? undefined
        : {
            active: mapping.subject.isActiveStatus(row[mapping.subject.status]),
            securityRevision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
              row[mapping.subject.securityRevision],
            ),
          },
    identifierCurrent:
      input.credential === undefined ||
      (identifier !== undefined &&
        mapping.identifier.isCurrent(identifier) &&
        mapping.subjectId.equals(
          identifier[mapping.identifier.subjectId],
          locked.nativeSubjectId,
        ) &&
        identifier[mapping.identifier.bindingRevision] ===
          input.credential.identifierBindingRevision),
    credentials: yield* Effect.forEach(credentials, (actual) =>
      Effect.gen(function* () {
        return {
          credentialId: yield* Schema.decodeUnknownEffect(Schema.String)(
            actual[mapping.authorityCredential.credentialId],
          ),
          revision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
            actual[mapping.authorityCredential.revision],
          ),
          active:
            mapping.authorityCredential.status === undefined ||
            mapping.authorityCredential.isActiveStatus?.(
              actual[mapping.authorityCredential.status],
            ) === true,
        };
      }),
    ),
    snapshot:
      row === undefined || identifier === undefined || credential === undefined
        ? Effect.succeed(undefined)
        : mapping.credential
            .decode({ moduleId: input.moduleId, subject: row, identifier, credential })
            .pipe(Effect.flatMap(snapshotPasswordCredential)),
    requirement:
      row === undefined
        ? Effect.fail(unavailable())
        : mapping.subject.decodeActionRequirement(row, action),
  };

  return { ...locked, credential, facts };
});

export const validateMutationAuthority = Effect.fn("DrizzlePassword.validateMutationAuthority")(
  function* (
    mapping: Mapping,
    configuration: PasswordSqlConfiguration,
    input: PasswordMutationInput,
    action: PasswordAction,
  ) {
    const current = yield* readMutationAuthority(mapping, configuration, input, action);
    const now = yield* validatePasswordMutation(mapping, input, action, current.facts);

    return now === undefined ? undefined : { ...current, now };
  },
);

export const commandExists = Effect.fn("Drizzle.commandExists")(function* (
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

export const insertCommand = Effect.fn("Drizzle.insertCommand")(function* (
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

export const mutationPostconditions = Effect.fn("DrizzlePassword.mutationPostconditions")(
  function* (
    mapping: Mapping,
    input: PasswordMutationInput,
    nativeSubjectId: unknown,
    subject: any,
    authorityCredential: any,
    credential: any,
    identifier: any,
    commands: ReadonlyArray<any>,
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
      if (
        identifier === undefined ||
        !mapping.identifier.isCurrent(identifier) ||
        !mapping.subjectId.equals(identifier[mapping.identifier.subjectId], nativeSubjectId) ||
        identifier[mapping.identifier.bindingRevision] !==
          input.credential.identifierBindingRevision
      )
        return false;

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
    const row = commands[0];

    return (
      commands.length === 1 &&
      row[mapping.command.action] === input.authorization.challenge.action &&
      row[mapping.command.bindingDigest] === input.authorization.challenge.bindingDigest &&
      row[mapping.command.decision] === "changed" &&
      (yield* mapping.decodeInstant(row[mapping.command.retentionUntil])) ===
        now + mapping.commandRetentionMillis
    );
  },
);

export const addPasswordIn = Effect.fn("DrizzlePassword.addPasswordIn")(function* (
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
  const authority = yield* validateMutationAuthority(mapping, configuration, input, "add-password");

  if (authority === undefined) return false;
  if ((yield* commandExists(mapping, input.moduleId, input.commandId, true)).length) return false;
  if (
    (yield* readPasswordCredential(mapping, input.moduleId, authority.nativeSubjectId, true)).length
  )
    return false;

  return yield* writeAddition(
    mapping,
    input,
    authority.nativeSubjectId,
    revisions,
    commandNow ?? authority.now,
  );
});

export const writeAddition = Effect.fn("DrizzlePassword.writeAddition")(function* (
  mapping: Mapping,
  input: PasswordMutationInput,
  nativeSubjectId: unknown,
  revisions: {
    readonly credentialId: string;
    readonly credentialRevision: SecurityRevision;
    readonly verifierVersion: SecurityRevision;
    readonly nextSecurityRevision: SecurityRevision;
  },
  commandNow: number,
) {
  const database = yield* CurrentPasswordSql;
  const { credentialId, credentialRevision, verifierVersion, nextSecurityRevision } = revisions;

  yield* database.insert(mapping.credential.table).values(
    mapping.credential.encodeInsert({
      moduleId: input.moduleId,
      subjectId: nativeSubjectId,
      credentialId,
      credentialRevision,
      verifierVersion,
      replacement: input.replacement,
    }),
  );
  yield* database.insert(mapping.authorityCredential.table).values(
    mapping.authorityCredential.encodeInsert({
      subjectId: nativeSubjectId,
      credentialId,
      revision: credentialRevision,
    }),
  );
  yield* database
    .update(mapping.subject.table)
    .set(updateValues([[mapping.subject.securityRevision, nextSecurityRevision]]))
    .where(
      and(
        eq(subjectColumns(mapping).id, nativeSubjectId),
        eq(subjectColumns(mapping).securityRevision, input.expectedRevision.securityRevision),
      ),
    );
  yield* insertCommand(mapping, input, "add-password", commandNow);

  if (!(yield* checkMutationApplied(mapping, input, nativeSubjectId, revisions, commandNow)))
    return yield* unavailable();

  return true;
});

export const currentExpectedCredential = Effect.fn("DrizzlePassword.currentExpectedCredential")(
  function* (
    mapping: Mapping,
    input: PasswordMutationInput,
    nativeSubjectId: unknown,
    captured?: Record<string, unknown>,
  ) {
    if (input.credential === undefined) return false;

    const row =
      captured ??
      (yield* readPasswordCredential(mapping, input.moduleId, nativeSubjectId, true))[0];

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

export const checkMutationApplied = Effect.fn("DrizzlePassword.checkMutationApplied")(function* (
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
    s = subjectColumns(mapping),
    a = authorityCredentialColumns(mapping),
    i = identifierColumns(mapping),
    command = commandColumns(mapping);

  const [credentials, subjects, authorities, commands, identifiers] = yield* readSnapshots(
    database,
    [
      {
        table: mapping.credential.table,
        where: and(
          eq(c.moduleId, input.moduleId),
          eq(c.subjectId, nativeSubjectId),
          eq(c.credentialId, revisions.credentialId),
          eq(c.credentialRevision, revisions.credentialRevision),
          eq(c.verifierVersion, revisions.verifierVersion),
          eq(c.verifier, Redacted.value(input.replacement.verifier)),
          eq(c.normalization, input.replacement.normalization),
        ),
        limit: 1,
      },
      {
        table: mapping.subject.table,
        where: and(
          eq(s.id, nativeSubjectId),
          eq(s.securityRevision, revisions.nextSecurityRevision),
        ),
        limit: 1,
      },
      {
        table: mapping.authorityCredential.table,
        where: and(
          eq(a.subjectId, nativeSubjectId),
          eq(a.credentialId, revisions.credentialId),
          eq(a.revision, revisions.credentialRevision),
        ),
        limit: 1,
      },
      {
        table: mapping.command.table,
        where: and(eq(command.moduleId, input.moduleId), eq(command.commandId, input.commandId)),
        limit: 1,
      },
      ...(input.credential === undefined
        ? []
        : [
            {
              table: mapping.identifier.table,
              where: and(
                eq(i.namespace, input.credential.identifier.namespace),
                eq(i.value, input.credential.identifier.value),
              ),
              limit: 1,
            },
          ]),
    ],
  ).rows;

  const credential = credentials?.[0];

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
      subjects?.[0],
      authorities?.[0],
      credential,
      identifiers?.[0],
      commands ?? [],
      now,
    ))
  );
});

export const writeReplacement = Effect.fn("DrizzlePassword.writeReplacement")(function* (
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
