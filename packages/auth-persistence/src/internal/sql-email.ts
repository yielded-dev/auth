import {
  EmailUnavailable,
  snapshotEmailCredential,
  type EmailAddressMutation,
  type EmailAddressTarget,
  type EmailCredentialSnapshot,
} from "@yielded/auth/Email";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import { AuthenticationRevision, SecurityRevision } from "@yielded/auth/Sessions";
import { Effect, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";

import type { EmailWorkflowOptions } from "./email-policy";
import type { EmailAddressRequest, EmailAddressStore, EmailMutationRevisions } from "./email-store";
import type { AnyEmailAddressMapping } from "./models/email-model";
import type { AnyProofPersistenceMapping } from "./models/proof-model";
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

type Row = Readonly<Record<string, unknown>>;
interface AddressRead {
  readonly native: unknown;
  readonly subject: Row;
  readonly target: EmailAddressTarget;
  readonly source?: {
    readonly credential: Row;
    readonly identifier: Row;
    readonly snapshot: EmailCredentialSnapshot;
  };
  readonly targetIdentifier: Row | undefined;
  readonly targetCredential: Row | undefined;
}

export const makeSqlEmailOwner = (
  client: SqlClient,
  mapping: AnyEmailAddressMapping,
  options: EmailWorkflowOptions & { readonly maxParameters?: number },
  proofMapping?: AnyProofPersistenceMapping,
): PersistenceOwner<EmailAddressStore> => {
  const sql = client.withoutTransforms();

  const subjects = requireSqlTable(mapping.subject.table),
    identifiers = requireSqlTable(mapping.identifier.table),
    credentials = requireSqlTable(mapping.credential.table),
    authorities = requireSqlTable(mapping.authorityCredential.table),
    commands = requireSqlTable(mapping.command.table);

  const proof =
    proofMapping === undefined
      ? undefined
      : makeSqlProofOwner(sql, proofMapping, { ...options, standaloneGuard: Effect.void });

  const aliases = {
    email_subject: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_subject"),
    ),
    email_identifier_first: sqlName(
      sql,
      sqlAlias(
        [subjects, identifiers, credentials, authorities, commands],
        "email_identifier_first",
      ),
    ),
    email_identifier_second: sqlName(
      sql,
      sqlAlias(
        [subjects, identifiers, credentials, authorities, commands],
        "email_identifier_second",
      ),
    ),
    email_source: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_source"),
    ),
    email_target: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_target"),
    ),
    email_authority: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_authority"),
    ),
    email_cardinality: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_cardinality"),
    ),
    email_command: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_command"),
    ),
    email_membership: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_membership"),
    ),
    email_completion: sqlName(
      sql,
      sqlAlias([subjects, identifiers, credentials, authorities, commands], "email_completion"),
    ),
  };

  const c = (table: Table, key: string, alias?: string) => sqlColumn(sql, table, key, alias),
    t = (table: Table) => sqlTable(sql, table),
    v = (table: Table, key: string, value: unknown) => sqlValue(sql, table, key, value);

  const projection = (table: Table, alias?: string, prefix = "") =>
    sqlProjection(sql, table, alias, prefix);

  const absent = (table: Table, prefix: string) =>
    sql.csv(Object.keys(table.columns).map((key) => sql`null as ${sqlName(sql, prefix + key)}`));

  const lock = (locking = options.locking) =>
    locking ? sql.onDialectOrElse({ pg: () => sql`for update`, orElse: () => sql`` }) : sql``;

  const selected = (table: Table, row: Row | undefined, prefix: string, key: string) =>
    row === undefined || row[key] === null
      ? Effect.succeed(undefined)
      : decodeSqlRow(table, row, prefix);

  const sameIdentifier = (left: LoginIdentifier, right: LoginIdentifier) =>
    left.namespace === right.namespace && left.value === right.value;

  const addressQuery = (
    input: EmailAddressRequest,
    native: unknown,
    locking: boolean,
    sourceIdentifier: LoginIdentifier | undefined,
    commandId?: string,
    enforceOwnership = false,
  ) => {
    const requested = [input.target, ...(sourceIdentifier === undefined ? [] : [sourceIdentifier])]
      .filter((item, index, all) => all.findIndex((other) => sameIdentifier(item, other)) === index)
      .sort((a, b) => `${a.namespace}\0${a.value}`.localeCompare(`${b.namespace}\0${b.value}`));

    const first = requested[0]!;
    const second = requested[1];
    const materialized = locking ? sql`materialized` : sql``;

    const statement = sql`with ${aliases.email_subject} as ${materialized} (
      select * from ${t(subjects)} where ${c(subjects, mapping.subject.id)}=${v(subjects, mapping.subject.id, native)} limit 1 ${lock(locking)}
    ), ${aliases.email_identifier_first} as ${materialized} (
      select * from ${t(identifiers)} where ${c(identifiers, mapping.identifier.namespace)}=${first.namespace} and ${c(identifiers, mapping.identifier.value)}=${first.value} and ${enforceOwnership ? sql`${c(identifiers, mapping.identifier.subjectId)} = ${v(identifiers, mapping.identifier.subjectId, native)}` : sql`true`} and (select count(*) from ${aliases.email_subject})>=0 limit 1 ${lock(locking)}
    ), ${aliases.email_identifier_second} as ${materialized} (
      select * from ${t(identifiers)} where ${second === undefined ? sql`false` : sql`${c(identifiers, mapping.identifier.namespace)}=${second.namespace} and ${c(identifiers, mapping.identifier.value)}=${second.value}`} and ${enforceOwnership ? sql`${c(identifiers, mapping.identifier.subjectId)} = ${v(identifiers, mapping.identifier.subjectId, native)}` : sql`true`} and (select count(*) from ${aliases.email_identifier_first})>=0 limit 1 ${lock(locking)}
    ), ${aliases.email_source} as ${materialized} (
      select * from ${t(credentials)} where ${input.sourceCredentialId === undefined ? sql`false` : sql`${c(credentials, mapping.credential.moduleId)}=${input.moduleId} and ${c(credentials, mapping.credential.credentialId)}=${input.sourceCredentialId}`} and ${enforceOwnership ? sql`${c(credentials, mapping.credential.subjectId)} = ${v(credentials, mapping.credential.subjectId, native)}` : sql`true`} and (select count(*) from ${aliases.email_identifier_second})>=0 limit 1 ${lock(locking)}
    ), ${aliases.email_target} as ${materialized} (
      select * from ${t(credentials)} where ${c(credentials, mapping.credential.moduleId)}=${input.moduleId} and ${c(credentials, mapping.credential.identifierNamespace)}=${input.target.namespace} and ${c(credentials, mapping.credential.identifierValue)}=${input.target.value} and ${enforceOwnership ? sql`${c(credentials, mapping.credential.subjectId)} = ${v(credentials, mapping.credential.subjectId, native)}` : sql`true`} and (select count(*) from ${aliases.email_source})>=0 limit 1 ${lock(locking)}
    ), ${aliases.email_authority} as ${materialized} (
      select * from ${t(authorities)} where ${c(authorities, mapping.authorityCredential.subjectId)}=${v(authorities, mapping.authorityCredential.subjectId, native)} and (select count(*) from ${aliases.email_target})>=0 order by ${c(authorities, mapping.authorityCredential.credentialId)} ${lock(locking)}
    ), ${aliases.email_cardinality} as ${materialized} (
      select * from ${t(credentials)} where ${mapping.addressCardinality === "single" && input.sourceCredentialId === undefined ? sql`${c(credentials, mapping.credential.moduleId)}=${input.moduleId} and ${c(credentials, mapping.credential.subjectId)}=${v(credentials, mapping.credential.subjectId, native)}` : sql`false`} and (select count(*) from ${aliases.email_authority})>=0 ${lock(locking)}
    ), ${aliases.email_command} as ${materialized} (
      select * from ${t(commands)} where ${commandId === undefined ? sql`false` : sql`${c(commands, mapping.command.moduleId)}=${input.moduleId} and ${c(commands, mapping.command.commandId)}=${commandId}`} and (select count(*) from ${aliases.email_cardinality})>=0 limit 1 ${lock(locking)}
    ), ${aliases.email_membership} as (
      select 0 as kind, ${projection(authorities, "a", "authority_")}, ${absent(credentials, "cardinality_")} from ${aliases.email_authority} as a
      union all select 1 as kind, ${absent(authorities, "authority_")},${projection(credentials, "c", "cardinality_")} from ${aliases.email_cardinality} as c
    ) select ${projection(subjects, "s", "subject_")},
      ${projection(identifiers, "i", "first_")},
      ${projection(identifiers, "j", "second_")},
      ${projection(credentials, "source", "source_")},
      ${projection(credentials, "target", "target_")},
      ${projection(commands, "r", "command_")},m.*
    from (select 1) as root left join ${aliases.email_subject} as s on true left join ${aliases.email_identifier_first} as i on true left join ${aliases.email_identifier_second} as j on true left join ${aliases.email_source} as source on true left join ${aliases.email_target} as target on true left join ${aliases.email_command} as r on true left join ${aliases.email_membership} as m on true`;

    const decode = Effect.fnUntraced(function* (rows: ReadonlyArray<Row>) {
      const firstRow = yield* selected(
        identifiers,
        rows[0],
        "first_",
        "first_" + mapping.identifier.namespace,
      );

      const secondRow = yield* selected(
        identifiers,
        rows[0],
        "second_",
        "second_" + mapping.identifier.namespace,
      );

      return {
        subject: yield* selected(subjects, rows[0], "subject_", "subject_" + mapping.subject.id),
        targetIdentifier: sameIdentifier(first, input.target) ? firstRow : secondRow,
        sourceIdentifier:
          sourceIdentifier === undefined
            ? undefined
            : sameIdentifier(first, sourceIdentifier)
              ? firstRow
              : secondRow,
        sourceCredential: yield* selected(
          credentials,
          rows[0],
          "source_",
          "source_" + mapping.credential.credentialId,
        ),
        targetCredential: yield* selected(
          credentials,
          rows[0],
          "target_",
          "target_" + mapping.credential.credentialId,
        ),
        command: yield* selected(
          commands,
          rows[0],
          "command_",
          "command_" + mapping.command.commandId,
        ),
        authority: yield* Effect.forEach(
          rows.filter((row) => Number(row.kind) === 0 && row.kind !== null),
          (row) => decodeSqlRow(authorities, row, "authority_"),
        ),
        cardinality: yield* Effect.forEach(
          rows.filter((row) => Number(row.kind) === 1),
          (row) => decodeSqlRow(credentials, row, "cardinality_"),
        ),
      };
    });

    return { statement, decode };
  };

  const revision = Effect.fnUntraced(function* (
    native: unknown,
    subject: Row | undefined,
    authority: ReadonlyArray<Row>,
  ) {
    if (subject === undefined || !mapping.subject.isActiveStatus(subject[mapping.subject.status]))
      return undefined;

    return yield* Schema.decodeUnknownEffect(AuthenticationRevision)({
      subjectId: yield* mapping.subjectId.toSubject(native),
      securityRevision: subject[mapping.subject.securityRevision],
      credentials: authority
        .filter((row) =>
          mapping.authorityCredential.isActiveStatus(row[mapping.authorityCredential.status]),
        )
        .map((row) => ({
          credentialId: row[mapping.authorityCredential.credentialId],
          revision: row[mapping.authorityCredential.revision],
        })),
    });
  });

  const currentAddress = Effect.fnUntraced(function* (
    input: EmailAddressRequest,
    locking: boolean,
    commandId?: string,
  ) {
    const native = yield* mapping.subjectId.toNative(input.subjectId);
    let sourceIdentifier: LoginIdentifier | undefined;

    if (input.sourceCredentialId !== undefined) {
      const subjectsRead =
        yield* sql`select ${projection(subjects)} from ${t(subjects)} where ${c(subjects, mapping.subject.id)}=${v(subjects, mapping.subject.id, native)} limit 1 ${lock(locking)}`;

      if (subjectsRead[0] === undefined) return undefined;
      const subject = yield* decodeSqlRow(subjects, subjectsRead[0]);

      if (!mapping.subject.isActiveStatus(subject[mapping.subject.status])) return undefined;

      const sourceRows =
        yield* sql`select ${projection(credentials)} from ${t(credentials)} where ${c(credentials, mapping.credential.moduleId)}=${input.moduleId} and ${c(credentials, mapping.credential.credentialId)}=${input.sourceCredentialId} limit 1`;

      if (sourceRows[0] !== undefined) {
        const source = yield* decodeSqlRow(credentials, sourceRows[0]);

        sourceIdentifier = yield* Schema.decodeUnknownEffect(
          Schema.Struct({ namespace: Schema.String, value: Schema.String }),
        )({
          namespace: source[mapping.credential.identifierNamespace],
          value: source[mapping.credential.identifierValue],
        });
      }
    }
    const query = addressQuery(input, native, locking, sourceIdentifier, commandId);
    const read = yield* query.decode(yield* query.statement);
    const currentRevision = yield* revision(native, read.subject, read.authority);

    if (currentRevision === undefined || read.subject === undefined) return undefined;

    const targetOwned =
      read.targetIdentifier !== undefined &&
      mapping.subjectId.equals(read.targetIdentifier[mapping.identifier.subjectId], native);

    const mutable =
      targetOwned &&
      mapping.identifier.isMutableTarget(read.targetIdentifier!) &&
      (read.targetCredential === undefined ||
        (!mapping.credential.isActiveStatus(read.targetCredential[mapping.credential.status]) &&
          mapping.subjectId.equals(read.targetCredential[mapping.credential.subjectId], native)));

    let source: AddressRead["source"];

    if (input.sourceCredentialId !== undefined) {
      if (
        read.sourceCredential === undefined ||
        sourceIdentifier === undefined ||
        !mapping.subjectId.equals(read.sourceCredential[mapping.credential.subjectId], native) ||
        !mapping.credential.isActiveStatus(read.sourceCredential[mapping.credential.status]) ||
        read.sourceIdentifier === undefined ||
        !mapping.identifier.isCurrent(read.sourceIdentifier) ||
        !mapping.subjectId.equals(read.sourceIdentifier[mapping.identifier.subjectId], native)
      )
        return undefined;

      const snapshot = yield* mapping.credential
        .decode({
          moduleId: input.moduleId,
          subject: read.subject,
          identifier: read.sourceIdentifier,
          credential: read.sourceCredential,
        })
        .pipe(Effect.flatMap(snapshotEmailCredential));

      source = { credential: read.sourceCredential, identifier: read.sourceIdentifier, snapshot };
    }

    const eligible =
      (read.targetIdentifier === undefined ? read.targetCredential === undefined : mutable) &&
      (input.sourceCredentialId === undefined || source !== undefined) &&
      (source === undefined || !sameIdentifier(source.snapshot.identifier, input.target)) &&
      !read.cardinality.some((row) =>
        mapping.credential.isActiveStatus(row[mapping.credential.status]),
      );

    const target: EmailAddressTarget = {
      revision: currentRevision,
      eligible,
      ...(source === undefined ? {} : { source: source.snapshot }),
      ...(mutable
        ? {
            targetIdentifierRevision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
              read.targetIdentifier![mapping.identifier.bindingRevision],
            ),
          }
        : {}),
    };

    return {
      native,
      subject: read.subject,
      target,
      ...(source === undefined ? {} : { source }),
      targetIdentifier: read.targetIdentifier,
      targetCredential: read.targetCredential,
      commandPresent: read.command !== undefined,
    };
  });

  const apply = Effect.fnUntraced(function* (
    input: EmailAddressMutation,
    action: "verify-address" | "change-address",
    current: AddressRead,
    allocated: EmailMutationRevisions,
    now: number,
  ) {
    const native = current.native;

    const targetCredentialId =
      current.targetCredential === undefined
        ? allocated.targetCredentialId
        : yield* Schema.decodeUnknownEffect(Schema.String)(
            current.targetCredential[mapping.credential.credentialId],
          );

    const source = current.source;

    if (action === "change-address") {
      if (source === undefined) return false;
      yield* sql`update ${t(identifiers)} set ${sqlUpdate(sql, identifiers, mapping.identifier.encodeRetirement({ source: source.snapshot.identifier, bindingRevision: allocated.sourceIdentifierRevision }))} where ${c(identifiers, mapping.identifier.namespace)}=${source.snapshot.identifier.namespace} and ${c(identifiers, mapping.identifier.value)}=${source.snapshot.identifier.value} and ${c(identifiers, mapping.identifier.subjectId)}=${v(identifiers, mapping.identifier.subjectId, native)} and ${c(identifiers, mapping.identifier.bindingRevision)}=${source.snapshot.identifierRevision}`;
      yield* sql`update ${t(credentials)} set ${sqlUpdate(sql, credentials, mapping.credential.encodeRetirement({ source: source.snapshot.identifier, credentialRevision: allocated.sourceCredentialRevision }))} where ${c(credentials, mapping.credential.moduleId)}=${input.moduleId} and ${c(credentials, mapping.credential.credentialId)}=${source.snapshot.credentialId} and ${c(credentials, mapping.credential.subjectId)}=${v(credentials, mapping.credential.subjectId, native)} and ${c(credentials, mapping.credential.credentialRevision)}=${source.snapshot.credentialRevision}`;
      yield* sql`update ${t(authorities)} set ${sqlUpdate(sql, authorities, mapping.authorityCredential.encodeRetirement(allocated.sourceCredentialRevision))} where ${c(authorities, mapping.authorityCredential.subjectId)}=${v(authorities, mapping.authorityCredential.subjectId, native)} and ${c(authorities, mapping.authorityCredential.credentialId)}=${source.snapshot.credentialId} and ${c(authorities, mapping.authorityCredential.revision)}=${source.snapshot.credentialRevision}`;
    }
    if (current.targetIdentifier === undefined)
      yield* sql`insert into ${t(identifiers)} ${sqlInsert(sql, identifiers, mapping.identifier.encodeVerifiedInsert({ identifier: input.target, subjectId: native, verifiedAtMillis: now, bindingRevision: allocated.targetIdentifierRevision }))}`;
    else
      yield* sql`update ${t(identifiers)} set ${sqlUpdate(sql, identifiers, mapping.identifier.encodeVerification({ verifiedAtMillis: now, bindingRevision: allocated.targetIdentifierRevision }))} where ${c(identifiers, mapping.identifier.namespace)}=${input.target.namespace} and ${c(identifiers, mapping.identifier.value)}=${input.target.value} and ${c(identifiers, mapping.identifier.subjectId)}=${v(identifiers, mapping.identifier.subjectId, native)} and ${c(identifiers, mapping.identifier.bindingRevision)}=${current.targetIdentifier[mapping.identifier.bindingRevision]}`;
    if (current.targetCredential === undefined) {
      yield* sql`insert into ${t(credentials)} ${sqlInsert(sql, credentials, mapping.credential.encodeVerifiedInsert({ moduleId: input.moduleId, subjectId: native, credentialId: targetCredentialId, identifier: input.target, credentialRevision: allocated.targetCredentialRevision }))}`;
      yield* sql`insert into ${t(authorities)} ${sqlInsert(sql, authorities, mapping.authorityCredential.encodeInsert({ subjectId: native, credentialId: targetCredentialId, revision: allocated.targetCredentialRevision }))}`;
    } else {
      const oldRevision = current.targetCredential[mapping.credential.credentialRevision];

      yield* sql`update ${t(credentials)} set ${sqlUpdate(sql, credentials, mapping.credential.encodeActivation({ identifier: input.target, credentialRevision: allocated.targetCredentialRevision }))} where ${c(credentials, mapping.credential.moduleId)}=${input.moduleId} and ${c(credentials, mapping.credential.credentialId)}=${targetCredentialId} and ${c(credentials, mapping.credential.subjectId)}=${v(credentials, mapping.credential.subjectId, native)} and ${c(credentials, mapping.credential.credentialRevision)}=${oldRevision}`;
      yield* sql`update ${t(authorities)} set ${sqlUpdate(sql, authorities, mapping.authorityCredential.encodeActivation(allocated.targetCredentialRevision))} where ${c(authorities, mapping.authorityCredential.subjectId)}=${v(authorities, mapping.authorityCredential.subjectId, native)} and ${c(authorities, mapping.authorityCredential.credentialId)}=${targetCredentialId} and ${c(authorities, mapping.authorityCredential.revision)}=${oldRevision}`;
    }
    yield* sql`update ${t(subjects)} set ${sqlUpdate(sql, subjects, { [mapping.subject.securityRevision]: allocated.nextSecurityRevision })} where ${c(subjects, mapping.subject.id)}=${v(subjects, mapping.subject.id, native)} and ${c(subjects, mapping.subject.securityRevision)}=${input.captured.revision.securityRevision}`;
    yield* sql`insert into ${t(commands)} ${sqlInsert(sql, commands, mapping.command.encodeInsert({ moduleId: input.moduleId, commandId: input.commandId, action, bindingDigest: input.authorization.challenge.bindingDigest, retentionUntilMillis: now + mapping.commandRetentionMillis }))}`;

    const query = addressQuery(
      {
        moduleId: input.moduleId,
        subjectId: input.captured.revision.subjectId,
        target: input.target,
        ...(source === undefined ? {} : { sourceCredentialId: source.snapshot.credentialId }),
      },
      native,
      false,
      source?.snapshot.identifier,
      input.commandId,
      true,
    );

    const after = yield* query.decode(yield* query.statement);

    // SQL computes membership markers so mapped collations retain authority.
    const marked =
      yield* sql`select ${projection(authorities)},case when ${c(authorities, mapping.authorityCredential.credentialId)}=${targetCredentialId} then 1 else 0 end as target_match,case when ${source === undefined ? sql`false` : sql`${c(authorities, mapping.authorityCredential.credentialId)}=${source.snapshot.credentialId}`} then 1 else 0 end as source_match from ${t(authorities)} where ${c(authorities, mapping.authorityCredential.subjectId)}=${v(authorities, mapping.authorityCredential.subjectId, native)} and ${c(authorities, mapping.authorityCredential.credentialId)} in ${sql.in(source === undefined ? [targetCredentialId] : [targetCredentialId, source.snapshot.credentialId])}`;

    const targets = marked.filter((row) => Number(row.target_match) === 1);
    const sources = marked.filter((row) => Number(row.source_match) === 1);

    const targetAuthority =
      targets.length === 1 ? yield* decodeSqlRow(authorities, targets[0]!) : undefined;

    const sourceAuthority =
      sources.length === 1 ? yield* decodeSqlRow(authorities, sources[0]!) : undefined;

    if (
      after.subject === undefined ||
      after.targetIdentifier === undefined ||
      after.targetCredential === undefined ||
      after.command === undefined ||
      targetAuthority === undefined ||
      !mapping.subjectId.equals(after.subject[mapping.subject.id], native) ||
      !mapping.subject.isActiveStatus(after.subject[mapping.subject.status]) ||
      after.subject[mapping.subject.securityRevision] !== allocated.nextSecurityRevision ||
      after.targetIdentifier[mapping.identifier.bindingRevision] !==
        allocated.targetIdentifierRevision ||
      (yield* mapping.decodeInstant(after.targetIdentifier[mapping.identifier.verifiedAt])) !==
        now ||
      !mapping.identifier.isCurrent(after.targetIdentifier) ||
      after.targetCredential[mapping.credential.credentialId] !== targetCredentialId ||
      after.targetCredential[mapping.credential.credentialRevision] !==
        allocated.targetCredentialRevision ||
      !mapping.subjectId.equals(after.targetCredential[mapping.credential.subjectId], native) ||
      !mapping.credential.isActiveStatus(after.targetCredential[mapping.credential.status]) ||
      targetAuthority[mapping.authorityCredential.revision] !==
        allocated.targetCredentialRevision ||
      !mapping.authorityCredential.isActiveStatus(
        targetAuthority[mapping.authorityCredential.status],
      ) ||
      after.command[mapping.command.action] !== action ||
      after.command[mapping.command.bindingDigest] !==
        input.authorization.challenge.bindingDigest ||
      (yield* mapping.decodeInstant(after.command[mapping.command.retentionUntil])) !==
        now + mapping.commandRetentionMillis
    )
      return false;

    return (
      action === "verify-address" ||
      (after.sourceCredential !== undefined &&
        after.sourceIdentifier !== undefined &&
        sourceAuthority !== undefined &&
        after.sourceCredential[mapping.credential.credentialRevision] ===
          allocated.sourceCredentialRevision &&
        !mapping.credential.isActiveStatus(after.sourceCredential[mapping.credential.status]) &&
        mapping.subjectId.equals(after.sourceIdentifier[mapping.identifier.subjectId], native) &&
        after.sourceIdentifier[mapping.identifier.bindingRevision] ===
          allocated.sourceIdentifierRevision &&
        !mapping.identifier.isCurrent(after.sourceIdentifier) &&
        sourceAuthority[mapping.authorityCredential.revision] ===
          allocated.sourceCredentialRevision &&
        !mapping.authorityCredential.isActiveStatus(
          sourceAuthority[mapping.authorityCredential.status],
        ))
    );
  });

  const store: EmailAddressStore = {
    ...(proof === undefined ? {} : { proof: proof.read }),
    readAddress: (input, locking) =>
      currentAddress(input, locking).pipe(Effect.map((current) => current?.target)),
    readMutation: (input, action) =>
      Effect.gen(function* () {
        const current = yield* currentAddress(
          {
            moduleId: input.moduleId,
            subjectId: input.captured.revision.subjectId,
            target: input.target,
            ...(input.captured.source === undefined
              ? {}
              : { sourceCredentialId: input.captured.source.credentialId }),
          },
          options.locking,
          input.commandId,
        );

        return current === undefined
          ? undefined
          : {
              target: current.target,
              requirement: mapping.subject.decodeActionRequirement(current.subject, action),
              commandPresent: current.commandPresent,
              applyMutation: (allocated: EmailMutationRevisions, now: number) =>
                apply(input, action, current, allocated, now),
            };
      }),
    readCompletion: (input) =>
      Effect.gen(function* () {
        if (proof === undefined || input.binding._tag !== "IdentifierChange")
          return yield* EmailUnavailable.make({});
        const binding = input.binding;
        const native = yield* mapping.subjectId.toNative(binding.revision.subjectId);
        const completion = yield* proof.completionQuery(input, false);

        const rows =
          yield* sql`with ${aliases.email_completion} as (${completion.statement}) select p.*,${projection(subjects, "s", "email_subject_")},${projection(authorities, "a", "email_authority_")} from ${aliases.email_completion} as p left join ${t(subjects)} as s on ${c(subjects, mapping.subject.id, "s")}=${v(subjects, mapping.subject.id, native)} left join ${t(authorities)} as a on ${c(authorities, mapping.authorityCredential.subjectId, "a")}=${v(authorities, mapping.authorityCredential.subjectId, native)}`;

        // Both reads include factors; collapse repeated rows by the stored key.
        const unique = (key: string) =>
          rows.filter(
            (row, index) =>
              row[key] !== null &&
              rows.findIndex((other) => Object.is(other[key], row[key])) === index,
          );

        const subject = yield* selected(
          subjects,
          rows[0],
          "email_subject_",
          "email_subject_" + mapping.subject.id,
        );

        const authority = yield* Effect.forEach(
          unique("email_authority_" + mapping.authorityCredential.credentialId),
          (row) => decodeSqlRow(authorities, row, "email_authority_"),
        );

        const proofRows =
          input.binding.revision.credentials.length === 0
            ? rows.slice(0, 1)
            : unique("credential_key");

        return {
          revision: yield* revision(native, subject, authority),
          completion: yield* completion.decode(
            proofRows.length === 0 ? rows.slice(0, 1) : proofRows,
          ),
        };
      }),
    readExpired: (input) =>
      Effect.gen(function* () {
        const cutoff = mapping.encodeInstant(input.nowMillis);

        const rows =
          yield* sql`select ${c(commands, mapping.command.commandId)} as id from ${t(commands)} where ${c(commands, mapping.command.moduleId)}=${input.moduleId} and ${c(commands, mapping.command.retentionUntil)}<=${cutoff} limit ${input.limit + 1} ${lock()}`;

        const selected = rows.slice(0, input.limit);

        return {
          result: { removed: selected.length, hasMore: rows.length > input.limit },
          deleteExpired:
            selected.length === 0
              ? Effect.void
              : sql`delete from ${t(commands)} where ${c(commands, mapping.command.moduleId)}=${input.moduleId} and ${c(commands, mapping.command.commandId)} in ${sql.in(selected.map((row) => row.id))} and ${c(commands, mapping.command.retentionUntil)}<=${cutoff}`.pipe(
                  Effect.asVoid,
                ),
        };
      }),
  };

  return {
    read: store,
    transaction: (body) => sql.withTransaction(body(store)),
  };
};
