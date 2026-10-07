import type { LoginIdentifier } from "@yielded/auth/Identity";
import {
  PasswordUnavailable,
  snapshotPasswordCredential,
  type PasswordMutationInput,
} from "@yielded/auth/Password";
import type { SubjectId } from "@yielded/auth/Schema";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { Effect, Redacted, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";
import type { Statement } from "effect/sql/Statement";

import type { AnyPasswordPersistenceMapping } from "./models/password-model";
import type { AnyProofPersistenceMapping } from "./models/proof-model";
import type { PasswordWorkflowOptions } from "./password-policy";
import type { PasswordMutationRevisions, PasswordStore } from "./password-store";
import type { PersistenceOwner } from "./persistence-owner";
import {
  decodeSqlRow,
  sqlAlias,
  requireSqlTable,
  sqlColumn,
  sqlInsert,
  sqlName,
  sqlProjection,
  sqlTable,
  sqlUpdate,
  sqlValue,
} from "./sql-metadata";
import { makeSqlProofOwner } from "./sql-proof";
import type { Table } from "./sql-table";

export const makeSqlPasswordOwner = (
  client: SqlClient,
  mapping: AnyPasswordPersistenceMapping,
  options: PasswordWorkflowOptions & { readonly maxParameters?: number },
  proofMapping?: AnyProofPersistenceMapping,
): PersistenceOwner<PasswordStore> => {
  const sql = client.withoutTransforms();
  const subjects = requireSqlTable(mapping.subject.table);
  const identifiers = requireSqlTable(mapping.identifier.table);
  const passwords = requireSqlTable(mapping.credential.table);
  const authorities = requireSqlTable(mapping.authorityCredential.table);
  const commands = requireSqlTable(mapping.command.table);

  const proof =
    proofMapping === undefined
      ? undefined
      : makeSqlProofOwner(sql, proofMapping, { ...options, standaloneGuard: Effect.void });

  const aliases = {
    password_subject: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "password_subject"),
    ),
    password_identifier: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "password_identifier"),
    ),
    password_credential: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "password_credential"),
    ),
    mutation_subject: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "mutation_subject"),
    ),
    mutation_identifier: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "mutation_identifier"),
    ),
    mutation_authority: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "mutation_authority"),
    ),
    mutation_password: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "mutation_password"),
    ),
    mutation_command: sqlName(
      sql,
      sqlAlias([subjects, identifiers, passwords, authorities, commands], "mutation_command"),
    ),
  };

  const c = (table: Table, key: string, alias?: string) => sqlColumn(sql, table, key, alias);
  const t = (table: Table) => sqlTable(sql, table);
  const v = (table: Table, key: string, value: unknown) => sqlValue(sql, table, key, value);

  const projection = (table: Table, alias?: string, prefix = "") =>
    sqlProjection(sql, table, alias, prefix);

  const lock = (locking = options.locking) =>
    locking ? sql.onDialectOrElse({ pg: () => sql`for update`, orElse: () => sql`` }) : sql``;

  const first = (table: Table, statement: Statement<Readonly<Record<string, unknown>>>) =>
    statement.pipe(
      Effect.flatMap((rows) =>
        rows[0] === undefined ? Effect.succeed(undefined) : decodeSqlRow(table, rows[0]),
      ),
    );

  const fromProjection = (
    table: Table,
    row: Readonly<Record<string, unknown>> | undefined,
    prefix: string,
    marker: string,
  ) =>
    row === undefined || row[marker] === null
      ? Effect.succeed(undefined)
      : decodeSqlRow(table, row, prefix);

  const credentialQuery = (
    moduleId: string,
    identifier: LoginIdentifier,
    nativeSubject: unknown,
    locking: boolean,
  ) => {
    const materialized = locking ? sql`materialized` : sql``;

    return sql`with ${aliases.password_subject} as ${materialized} (
      select * from ${t(subjects)} where ${c(subjects, mapping.subject.id)} = ${v(subjects, mapping.subject.id, nativeSubject)} limit 1 ${lock(locking)}
    ), ${aliases.password_identifier} as ${materialized} (
      select * from ${t(identifiers)} where ${c(identifiers, mapping.identifier.namespace)} = ${identifier.namespace} and ${c(identifiers, mapping.identifier.value)} = ${identifier.value} and (select count(*) from ${aliases.password_subject}) >= 0 limit 1 ${lock(locking)}
    ), ${aliases.password_credential} as ${materialized} (
      select * from ${t(passwords)} where ${c(passwords, mapping.credential.moduleId)} = ${moduleId} and ${c(passwords, mapping.credential.subjectId)} = ${v(passwords, mapping.credential.subjectId, nativeSubject)} and (select count(*) from ${aliases.password_identifier}) >= 0 limit 1 ${lock(locking)}
    ) select ${projection(subjects, "s", "password_subject_")},
      ${projection(identifiers, "i", "password_identifier_")},
      ${projection(passwords, "p", "password_credential_")}
    from (select 1) as root left join ${aliases.password_subject} as s on true left join ${aliases.password_identifier} as i on true left join ${aliases.password_credential} as p on true`;
  };

  const decodeCredential = Effect.fnUntraced(function* (
    moduleId: string,
    nativeSubjectId: unknown,
    row: Readonly<Record<string, unknown>> | undefined,
    requestedSubjectId?: SubjectId,
  ) {
    const subject = yield* fromProjection(
      subjects,
      row,
      "password_subject_",
      "password_subject_" + mapping.subject.id,
    );

    if (subject === undefined || !mapping.subject.isActiveStatus(subject[mapping.subject.status]))
      return undefined;

    const identifier = yield* fromProjection(
      identifiers,
      row,
      "password_identifier_",
      "password_identifier_" + mapping.identifier.namespace,
    );

    if (
      identifier === undefined ||
      !mapping.identifier.isCurrent(identifier) ||
      !mapping.subjectId.equals(nativeSubjectId, identifier[mapping.identifier.subjectId])
    )
      return undefined;
    const subjectId = yield* mapping.subjectId.toSubject(nativeSubjectId);

    if (requestedSubjectId !== undefined && subjectId !== requestedSubjectId) return undefined;

    const credential = yield* fromProjection(
      passwords,
      row,
      "password_credential_",
      "password_credential_" + mapping.credential.credentialId,
    );

    const snapshot =
      credential === undefined
        ? undefined
        : yield* mapping.credential
            .decode({ moduleId, subject, identifier, credential })
            .pipe(Effect.flatMap(snapshotPasswordCredential));

    return { nativeSubjectId, subjectId, snapshot };
  });

  const resolve = Effect.fnUntraced(function* (
    input: Parameters<PasswordStore["readCredential"]>[0],
    locking: boolean,
  ) {
    const identifier =
      input.subjectId === undefined
        ? yield* first(
            identifiers,
            sql`select ${projection(identifiers)} from ${t(identifiers)} where ${c(identifiers, mapping.identifier.namespace)} = ${input.identifier.namespace} and ${c(identifiers, mapping.identifier.value)} = ${input.identifier.value} limit 1`,
          )
        : undefined;

    if (input.subjectId === undefined && identifier === undefined) return undefined;

    const native =
      input.subjectId === undefined
        ? identifier![mapping.identifier.subjectId]
        : yield* mapping.subjectId.toNative(input.subjectId);

    const rows = yield* credentialQuery(input.moduleId, input.identifier, native, locking);

    return yield* decodeCredential(input.moduleId, native, rows[0], input.subjectId);
  });

  const mutationQuery = (
    input: PasswordMutationInput,
    native: unknown,
    locking: boolean,
    expectedIds: ReadonlyArray<string>,
  ) => {
    const identifier = input.credential?.identifier;
    const materialized = locking ? sql`materialized` : sql``;

    return sql`with ${aliases.mutation_subject} as ${materialized} (
      select * from ${t(subjects)} where ${c(subjects, mapping.subject.id)} = ${v(subjects, mapping.subject.id, native)} limit 1 ${lock(locking)}
    ), ${aliases.mutation_identifier} as ${materialized} (
      select * from ${t(identifiers)} where ${identifier === undefined ? sql`false` : sql`${c(identifiers, mapping.identifier.namespace)} = ${identifier.namespace} and ${c(identifiers, mapping.identifier.value)} = ${identifier.value}`} and (select count(*) from ${aliases.mutation_subject}) >= 0 limit 1 ${lock(locking)}
    ), ${aliases.mutation_authority} as ${materialized} (
      select * from ${t(authorities)} where ${c(authorities, mapping.authorityCredential.subjectId)} = ${v(authorities, mapping.authorityCredential.subjectId, native)} and ${expectedIds.length === 0 ? sql`false` : sql`${c(authorities, mapping.authorityCredential.credentialId)} in ${sql.in(expectedIds)}`} and (select count(*) from ${aliases.mutation_identifier}) >= 0 order by ${c(authorities, mapping.authorityCredential.credentialId)} ${lock(locking)}
    ), ${aliases.mutation_password} as ${materialized} (
      select * from ${t(passwords)} where ${c(passwords, mapping.credential.moduleId)} = ${input.moduleId} and ${c(passwords, mapping.credential.subjectId)} = ${v(passwords, mapping.credential.subjectId, native)} and (select count(*) from ${aliases.mutation_authority}) >= 0 limit 1 ${lock(locking)}
    ), ${aliases.mutation_command} as ${materialized} (
      select * from ${t(commands)} where ${c(commands, mapping.command.moduleId)} = ${input.moduleId} and ${c(commands, mapping.command.commandId)} = ${input.commandId} and (select count(*) from ${aliases.mutation_password}) >= 0 limit 1 ${lock(locking)}
    ) select ${projection(subjects, "s", "subject_")},
      ${projection(identifiers, "i", "identifier_")},
      ${projection(authorities, "a", "authority_")},
      ${projection(passwords, "p", "password_")},
      ${projection(commands, "r", "command_")}
    from (select 1) as root left join ${aliases.mutation_subject} as s on true left join ${aliases.mutation_identifier} as i on true left join ${aliases.mutation_authority} as a on true left join ${aliases.mutation_password} as p on true left join ${aliases.mutation_command} as r on true order by ${c(authorities, mapping.authorityCredential.credentialId, "a")}`;
  };

  const applyMutation = Effect.fnUntraced(function* (
    input: PasswordMutationInput,
    native: unknown,
    revisions: PasswordMutationRevisions,
    now: number,
  ) {
    const old = input.credential;

    if (old === undefined) {
      yield* sql`insert into ${t(passwords)} ${sqlInsert(sql, passwords, mapping.credential.encodeInsert({ moduleId: input.moduleId, subjectId: native, ...revisions, replacement: input.replacement }))}`;
      yield* sql`insert into ${t(authorities)} ${sqlInsert(sql, authorities, mapping.authorityCredential.encodeInsert({ subjectId: native, credentialId: revisions.credentialId, revision: revisions.credentialRevision }))}`;
    } else {
      yield* sql`update ${t(passwords)} set ${sqlUpdate(sql, passwords, mapping.credential.encodeReplacement({ replacement: input.replacement, ...revisions }))} where ${c(passwords, mapping.credential.moduleId)} = ${input.moduleId} and ${c(passwords, mapping.credential.subjectId)} = ${v(passwords, mapping.credential.subjectId, native)} and ${c(passwords, mapping.credential.credentialId)} = ${old.credentialId} and ${c(passwords, mapping.credential.credentialRevision)} = ${old.credentialRevision} and ${c(passwords, mapping.credential.verifierVersion)} = ${old.verifierVersion} and ${c(passwords, mapping.credential.verifier)} = ${Redacted.value(old.verifier)} and ${c(passwords, mapping.credential.normalization)} = ${old.normalization}`;
    }
    yield* sql`update ${t(subjects)} set ${sqlUpdate(sql, subjects, { [mapping.subject.securityRevision]: revisions.nextSecurityRevision })} where ${c(subjects, mapping.subject.id)} = ${v(subjects, mapping.subject.id, native)} and ${c(subjects, mapping.subject.securityRevision)} = ${input.expectedRevision.securityRevision}`;
    if (old !== undefined)
      yield* sql`update ${t(authorities)} set ${sqlUpdate(sql, authorities, mapping.authorityCredential.encodeRevision(revisions.credentialRevision))} where ${c(authorities, mapping.authorityCredential.subjectId)} = ${v(authorities, mapping.authorityCredential.subjectId, native)} and ${c(authorities, mapping.authorityCredential.credentialId)} = ${old.credentialId} and ${c(authorities, mapping.authorityCredential.revision)} = ${old.credentialRevision}`;
    yield* sql`insert into ${t(commands)} ${sqlInsert(sql, commands, mapping.command.encodeInsert({ moduleId: input.moduleId, commandId: input.commandId, action: input.authorization.challenge.action, bindingDigest: input.authorization.challenge.bindingDigest, decision: "changed", retentionUntilMillis: now + mapping.commandRetentionMillis }))}`;
    const rows = yield* mutationQuery(input, native, false, [revisions.credentialId]);
    const row = rows[0];

    const subject = yield* fromProjection(
      subjects,
      row,
      "subject_",
      "subject_" + mapping.subject.id,
    );

    const authority = yield* fromProjection(
      authorities,
      row,
      "authority_",
      "authority_" + mapping.authorityCredential.credentialId,
    );

    const password = yield* fromProjection(
      passwords,
      row,
      "password_",
      "password_" + mapping.credential.credentialId,
    );

    const command = yield* fromProjection(
      commands,
      row,
      "command_",
      "command_" + mapping.command.commandId,
    );

    if (
      subject === undefined ||
      authority === undefined ||
      password === undefined ||
      command === undefined ||
      !mapping.subject.isActiveStatus(subject[mapping.subject.status]) ||
      subject[mapping.subject.securityRevision] !== revisions.nextSecurityRevision ||
      (mapping.authorityCredential.status !== undefined &&
        mapping.authorityCredential.isActiveStatus?.(
          authority[mapping.authorityCredential.status],
        ) !== true) ||
      authority[mapping.authorityCredential.revision] !== revisions.credentialRevision ||
      password[mapping.credential.credentialId] !== revisions.credentialId ||
      password[mapping.credential.credentialRevision] !== revisions.credentialRevision ||
      password[mapping.credential.verifierVersion] !== revisions.verifierVersion ||
      password[mapping.credential.verifier] !== Redacted.value(input.replacement.verifier) ||
      password[mapping.credential.normalization] !== input.replacement.normalization ||
      command[mapping.command.action] !== input.authorization.challenge.action ||
      command[mapping.command.bindingDigest] !== input.authorization.challenge.bindingDigest ||
      command[mapping.command.decision] !== "changed" ||
      (yield* mapping.decodeInstant(command[mapping.command.retentionUntil])) !==
        now + mapping.commandRetentionMillis
    )
      return false;
    if (old !== undefined) {
      const identifier = yield* fromProjection(
        identifiers,
        row,
        "identifier_",
        "identifier_" + mapping.identifier.namespace,
      );

      if (
        identifier === undefined ||
        !mapping.identifier.isCurrent(identifier) ||
        !mapping.subjectId.equals(identifier[mapping.identifier.subjectId], native) ||
        identifier[mapping.identifier.bindingRevision] !== old.identifierBindingRevision
      )
        return false;

      const decoded = yield* mapping.credential.decode({
        moduleId: input.moduleId,
        subject,
        identifier,
        credential: password,
      });

      if (decoded.identifierVerifiedAtMillis !== old.identifierVerifiedAtMillis) return false;
    }

    return true;
  });

  const store: PasswordStore = {
    ...(proof === undefined ? {} : { proof: proof.read }),
    readCredential: resolve,
    readForSubject: (input) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(input.subjectId);

        const rows =
          yield* sql`select ${projection(subjects, "s", "subject_")},${projection(passwords, "p", "password_")},${projection(identifiers, "i", "identifier_")} from ${t(subjects)} as s left join ${t(passwords)} as p on ${c(passwords, mapping.credential.moduleId, "p")} = ${input.moduleId} and ${c(passwords, mapping.credential.subjectId, "p")} = ${v(passwords, mapping.credential.subjectId, native)} left join ${t(identifiers)} as i on ${c(identifiers, mapping.identifier.subjectId, "i")} = ${v(identifiers, mapping.identifier.subjectId, native)} where ${c(subjects, mapping.subject.id, "s")} = ${v(subjects, mapping.subject.id, native)}`;

        if (rows[0] === undefined) return undefined;
        const subject = yield* decodeSqlRow(subjects, rows[0], "subject_");

        if (!mapping.subject.isActiveStatus(subject[mapping.subject.status])) return undefined;

        const credential = yield* fromProjection(
          passwords,
          rows[0],
          "password_",
          "password_" + mapping.credential.credentialId,
        );

        if (credential === undefined) return undefined;
        for (const row of rows) {
          const identifier = yield* fromProjection(
            identifiers,
            row,
            "identifier_",
            "identifier_" + mapping.identifier.namespace,
          );

          if (identifier !== undefined && mapping.identifier.isCurrent(identifier))
            return yield* mapping.credential
              .decode({ moduleId: input.moduleId, subject, identifier, credential })
              .pipe(Effect.flatMap(snapshotPasswordCredential));
        }

        return undefined;
      }),
    readMutation: (input, action) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(input.expectedRevision.subjectId);

        const expectedIds = [
          ...new Set(
            [
              ...input.expectedRevision.credentials,
              ...input.authorization.evidence.revision.credentials,
            ].map((item) => item.credentialId),
          ),
        ];

        const rows = yield* mutationQuery(input, native, options.locking, expectedIds);

        const subject = yield* fromProjection(
          subjects,
          rows[0],
          "subject_",
          "subject_" + mapping.subject.id,
        );

        const identifier = yield* fromProjection(
          identifiers,
          rows[0],
          "identifier_",
          "identifier_" + mapping.identifier.namespace,
        );

        const credential = yield* fromProjection(
          passwords,
          rows[0],
          "password_",
          "password_" + mapping.credential.credentialId,
        );

        const expected = input.credential;

        return {
          subject:
            subject === undefined
              ? undefined
              : {
                  active: mapping.subject.isActiveStatus(subject[mapping.subject.status]),
                  securityRevision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
                    subject[mapping.subject.securityRevision],
                  ),
                },
          identifierCurrent:
            identifier !== undefined &&
            mapping.identifier.isCurrent(identifier) &&
            mapping.subjectId.equals(native, identifier[mapping.identifier.subjectId]) &&
            (expected === undefined ||
              identifier[mapping.identifier.bindingRevision] ===
                expected.identifierBindingRevision),
          credentials: yield* Effect.forEach(
            rows.filter(
              (row) => row["authority_" + mapping.authorityCredential.credentialId] !== null,
            ),
            (row) =>
              Effect.gen(function* () {
                const value = yield* decodeSqlRow(authorities, row, "authority_");

                return {
                  credentialId: yield* Schema.decodeUnknownEffect(Schema.String)(
                    value[mapping.authorityCredential.credentialId],
                  ),
                  revision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
                    value[mapping.authorityCredential.revision],
                  ),
                  active:
                    mapping.authorityCredential.status === undefined ||
                    mapping.authorityCredential.isActiveStatus?.(
                      value[mapping.authorityCredential.status],
                    ) === true,
                };
              }),
          ),
          passwordPresent: credential !== undefined,
          expectedPasswordCurrent:
            expected !== undefined &&
            credential !== undefined &&
            credential[mapping.credential.credentialId] === expected.credentialId &&
            credential[mapping.credential.credentialRevision] === expected.credentialRevision &&
            credential[mapping.credential.verifierVersion] === expected.verifierVersion &&
            credential[mapping.credential.verifier] === Redacted.value(expected.verifier) &&
            credential[mapping.credential.normalization] === expected.normalization &&
            input.authorization.challenge.targetCredentialId === expected.credentialId,
          snapshot:
            subject === undefined || identifier === undefined || credential === undefined
              ? Effect.succeed(undefined)
              : mapping.credential
                  .decode({ moduleId: input.moduleId, subject, identifier, credential })
                  .pipe(Effect.flatMap(snapshotPasswordCredential)),
          requirement:
            subject === undefined
              ? Effect.fail(PasswordUnavailable.make({}))
              : mapping.subject.decodeActionRequirement(subject, action),
          commandPresent: rows[0]?.["command_" + mapping.command.commandId] !== null,
          applyMutation: (revisions, now) => applyMutation(input, native, revisions, now),
        };
      }),
    readReset: (input) =>
      Effect.gen(function* () {
        if (proof === undefined || input.binding._tag !== "Subject")
          return yield* PasswordUnavailable.make({});
        const binding = input.binding;
        const native = yield* mapping.subjectId.toNative(binding.revision.subjectId);
        const moduleId = input.moduleId.slice(0, -"/reset".length);
        const completion = yield* proof.completionQuery(input, false);
        const password = credentialQuery(moduleId, binding.identifier, native, false);

        const rows =
          yield* sql`select p.*, c.* from (${password}) as p cross join (${completion.statement}) as c`;

        const current = yield* decodeCredential(
          moduleId,
          native,
          rows[0],
          binding.revision.subjectId,
        );

        return { credential: current?.snapshot, completion: yield* completion.decode(rows) };
      }),
  };

  return {
    read: store,
    transaction: (body) => sql.withTransaction(body(store)),
  };
};
