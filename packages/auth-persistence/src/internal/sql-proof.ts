import { ProofUnavailable, ProofPurpose } from "@yielded/auth/Proofs";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { DateTime, Effect, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";
import type { Fragment, Statement } from "effect/sql/Statement";

import { jsonBatches } from "./json-batches";
import type { AnyProofPersistenceMapping } from "./models/proof-model";
import { allocateProofVersion, sameProofBinding, type ProofWorkflowOptions } from "./proof-policy";
import type {
  ProofAuthorityRead,
  ProofGenerationRead,
  ProofScopeRequest,
  ProofStore,
} from "./proof-store";
import {
  decodeSqlRow,
  sqlAlias,
  requireSqlTable,
  sqlColumn,
  sqlInsert,
  sqlInsertMany,
  sqlName,
  sqlProjection,
  sqlTable,
  sqlUpdate,
  sqlValue,
} from "./sql-metadata";
import type { Table } from "./sql-table";

const GenerationFields = Schema.Struct({
  moduleId: Schema.String,
  purpose: Schema.String,
  proofId: Schema.String,
  seriesKey: Schema.String,
  version: Schema.String,
  deliveryId: Schema.String,
  verifierKeyId: Schema.String,
  verifierDigest: Schema.String,
  state: Schema.Literals(["active", "consumed", "cancelled", "superseded"]),
  sendCount: Schema.Natural,
  deliveryState: Schema.Literals(["new", "claimed", "accepted", "failed", "ambiguous"]),
  deliveryRetryMillis: Schema.Natural,
  claimVersion: Schema.optional(Schema.String),
});

export const makeSqlProofOwner = (
  client: SqlClient,
  mapping: AnyProofPersistenceMapping,
  options: ProofWorkflowOptions,
) => {
  const sql = client.withoutTransforms();
  const requests = requireSqlTable(mapping.request.table);
  const series = requireSqlTable(mapping.series.table);
  const generations = requireSqlTable(mapping.generation.table);
  const continuations = requireSqlTable(mapping.continuation.table);
  const scopes = requireSqlTable(mapping.rateScope.table);
  const abuse = requireSqlTable(mapping.abuseEvent.table);
  const failures = requireSqlTable(mapping.failureEvent.table);
  const commands = requireSqlTable(mapping.command.table);
  const identifiers = requireSqlTable(mapping.authority.identifier.table);
  const subject = mapping.authority.subject;
  const subjects = subject === undefined ? undefined : requireSqlTable(subject.table);
  const credential = mapping.authority.credential;
  const credentials = credential === undefined ? undefined : requireSqlTable(credential.table);

  const aliases = {
    proof_subject: sqlName(
      sql,
      sqlAlias(
        [
          requests,
          series,
          generations,
          continuations,
          scopes,
          abuse,
          failures,
          commands,
          identifiers,
          subjects,
          credentials,
        ],
        "proof_subject",
      ),
    ),
    proof_identifiers: sqlName(
      sql,
      sqlAlias(
        [
          requests,
          series,
          generations,
          continuations,
          scopes,
          abuse,
          failures,
          commands,
          identifiers,
          subjects,
          credentials,
        ],
        "proof_identifiers",
      ),
    ),
    proof_credentials: sqlName(
      sql,
      sqlAlias(
        [
          requests,
          series,
          generations,
          continuations,
          scopes,
          abuse,
          failures,
          commands,
          identifiers,
          subjects,
          credentials,
        ],
        "proof_credentials",
      ),
    ),
    completion_authority: sqlName(
      sql,
      sqlAlias(
        [
          requests,
          series,
          generations,
          continuations,
          scopes,
          abuse,
          failures,
          commands,
          identifiers,
          subjects,
          credentials,
        ],
        "completion_authority",
      ),
    ),
    completion_series: sqlName(
      sql,
      sqlAlias(
        [
          requests,
          series,
          generations,
          continuations,
          scopes,
          abuse,
          failures,
          commands,
          identifiers,
          subjects,
          credentials,
        ],
        "completion_series",
      ),
    ),
    completion_continuation: sqlName(
      sql,
      sqlAlias(
        [
          requests,
          series,
          generations,
          continuations,
          scopes,
          abuse,
          failures,
          commands,
          identifiers,
          subjects,
          credentials,
        ],
        "completion_continuation",
      ),
    ),
  };

  const c = (table: Table, key: string, alias?: string) => sqlColumn(sql, table, key, alias);
  const t = (table: Table) => sqlTable(sql, table);

  const projection = (table: Table, alias?: string, prefix = "") =>
    sqlProjection(sql, table, alias, prefix);

  const lock = (locking = options.locking) =>
    locking ? sql.onDialectOrElse({ pg: () => sql`for update`, orElse: () => sql`` }) : sql``;

  const decodeRows = (table: Table, statement: Statement<Readonly<Record<string, unknown>>>) =>
    Effect.flatMap(statement, (rows) => Effect.forEach(rows, (row) => decodeSqlRow(table, row)));

  const decodeFirst = (table: Table, statement: Statement<Readonly<Record<string, unknown>>>) =>
    decodeRows(table, statement).pipe(Effect.map((rows) => rows[0]));

  const nativeInstant = mapping.encodeInstant;
  const instant = mapping.decodeInstant;

  const optionalInstant = (value: unknown) =>
    value === null || value === undefined ? Effect.succeed(undefined) : instant(value);

  const generationRead = Effect.fnUntraced(function* (row: Readonly<Record<string, unknown>>) {
    const fields = yield* Schema.decodeUnknownEffect(GenerationFields)({
      ...row,
      claimVersion: row.claimVersion ?? undefined,
    });

    return {
      ...fields,
      claimVersion: fields.claimVersion,
      expiresAtMillis: yield* instant(row.expiresAt),
      claimDeadlineMillis: yield* optionalInstant(row.claimDeadline),
      retryAtMillis: yield* optionalInstant(row.retryAt),
      binding: mapping.generation.decodeBinding(row),
    } satisfies ProofGenerationRead;
  });

  const readGeneration = Effect.fnUntraced(function* (
    moduleId: string,
    proofId: string,
    locking: boolean,
  ) {
    const row = yield* decodeFirst(
      generations,
      sql`select ${projection(generations)} from ${t(generations)} where ${c(generations, "moduleId")} = ${moduleId} and ${c(generations, "proofId")} = ${proofId} limit 1 ${lock(locking)}`,
    );

    return row === undefined ? undefined : yield* generationRead(row);
  });

  const recordScopes = (
    input: ProofScopeRequest,
    commandId: string,
    nowMillis: number,
    retentionUntilMillis: number,
  ) =>
    input.entries.length === 0
      ? Effect.void
      : sql`insert into ${t(abuse)} ${sqlInsertMany(
          sql,
          abuse,
          input.entries.map((entry) =>
            mapping.abuseEvent.encodeInsert({
              moduleId: input.moduleId,
              purpose: input.purpose,
              action: input.action,
              scopeKind: entry.kind,
              scopeKey: entry.key,
              commandId,
              occurredAtMillis: nowMillis,
              retentionUntilMillis,
            }),
          ),
        )}`.pipe(Effect.asVoid);

  const authorityQuery = Effect.fnUntraced(function* (
    input: Parameters<ProofStore["readAuthority"]>[0],
    locking: boolean,
  ) {
    const bound = input.binding._tag !== "Identifier";

    if (
      bound &&
      (subject === undefined ||
        subjects === undefined ||
        credential === undefined ||
        credentials === undefined ||
        mapping.authority.subjectId === undefined)
    )
      return yield* ProofUnavailable.make({});

    const nativeSubject =
      input.binding._tag === "Identifier"
        ? undefined
        : yield* mapping.authority.subjectId!.toNative(input.binding.revision.subjectId);

    const requested =
      input.binding._tag === "Identifier"
        ? []
        : [...input.binding.revision.credentials].sort((a, b) =>
            a.credentialId.localeCompare(b.credentialId),
          );

    const authority = bound
      ? sql`select * from ${t(subjects!)} where ${c(subjects!, subject!.id)} = ${sqlValue(sql, subjects!, subject!.id, nativeSubject)} limit 1 ${lock(locking)}`
      : sql`select 1 as present`;

    const credentialRows =
      requested.length === 0
        ? sql`select 1 as absent where false`
        : sql`select * from ${t(credentials!)} where ${c(credentials!, credential!.subjectId)} = ${sqlValue(sql, credentials!, credential!.subjectId, nativeSubject)} and ${c(credentials!, credential!.credentialId)} in ${sql.in(requested.map((item) => item.credentialId))} and (select count(*) from ${aliases.proof_identifiers}) >= 0 order by ${c(credentials!, credential!.credentialId)} ${lock(locking)}`;

    const materialized = locking ? sql`materialized` : sql``;

    const statement = sql`
        with ${aliases.proof_subject} as ${materialized} (${authority}),
        ${aliases.proof_identifiers} as ${materialized} (
          select * from ${t(identifiers)} where ${c(identifiers, "namespace")} = ${input.binding.identifier.namespace} and ${c(identifiers, "value")} = ${input.binding.identifier.value}
            and (select count(*) from ${aliases.proof_subject}) >= 0 ${lock(locking)}
        ), ${aliases.proof_credentials} as ${materialized} (${credentialRows})
        select ${bound ? sql`${projection(subjects!, "s", "subject_")},` : sql``}
          ${projection(identifiers, "i", "identifier_")}
          ${requested.length === 0 ? sql`` : sql`, ${projection(credentials!, "c", "credential_")}`}
        from (select 1) as root
        left join ${aliases.proof_subject} as s on true
        left join ${aliases.proof_identifiers} as i on true
        left join ${aliases.proof_credentials} as c on true
      `;

    const decode = Effect.fnUntraced(function* (
      rows: ReadonlyArray<Readonly<Record<string, unknown>>>,
    ) {
      const first = rows[0];

      const subjectRow =
        !bound || first === undefined || first["subject_" + subject!.id] === null
          ? undefined
          : yield* decodeSqlRow(subjects!, first, "subject_");

      const identifierRows =
        first === undefined || first["identifier_namespace"] === null
          ? []
          : [yield* decodeSqlRow(identifiers, first, "identifier_")];

      const actual =
        requested.length === 0
          ? []
          : yield* Effect.forEach(
              rows.filter((row) => row["credential_" + credential!.credentialId] !== null),
              (row) =>
                Effect.gen(function* () {
                  const decoded = yield* decodeSqlRow(credentials!, row, "credential_");

                  return {
                    credentialId: yield* Schema.decodeUnknownEffect(Schema.String)(
                      decoded[credential!.credentialId],
                    ),
                    revision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
                      decoded[credential!.revision],
                    ),
                    active:
                      credential!.status === undefined ||
                      credential!.isActiveStatus?.(decoded[credential!.status]) === true,
                  };
                }),
            );

      return {
        subject:
          subjectRow === undefined
            ? undefined
            : {
                active: subject!.isActiveStatus(subjectRow[subject!.status]),
                securityRevision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
                  subjectRow[subject!.securityRevision],
                ),
              },
        identifierCurrent: mapping.authority.identifier.isCurrent(
          {
            ...input,
            ...(nativeSubject === undefined ? {} : { nativeSubjectId: nativeSubject }),
          },
          identifierRows,
        ),
        credentials: actual,
      } satisfies ProofAuthorityRead;
    });

    return { statement, decode };
  });

  const completionQuery = Effect.fnUntraced(function* (
    input: Parameters<ProofStore["readCompletion"]>[0],
    mutating: boolean,
  ) {
    const authority = yield* authorityQuery(input, mutating && options.locking);
    const keys = mapping.scopeKeys(input);

    const statement = sql`with ${aliases.completion_authority} as materialized (${authority.statement}), ${aliases.completion_series} as materialized (
      select * from ${t(series)} where ${mutating ? sql`${c(series, "moduleId")} = ${input.moduleId} and ${c(series, "purpose")} = ${input.purpose} and ${c(series, "scopeKey")} = ${keys.series}` : sql`false`}
      and (select count(*) from ${aliases.completion_authority}) >= 0 limit 1 ${lock(mutating && options.locking)}
    ), ${aliases.completion_continuation} as materialized (
      select * from ${t(continuations)} where ${c(continuations, "moduleId")} = ${input.moduleId} and ${c(continuations, "continuationId")} = ${input.continuationId}
      and (select count(*) from ${aliases.completion_series}) >= 0 limit 1 ${lock(mutating && options.locking)}
    ) select a.*, ${projection(continuations, "continuation", "completion_")}, ${c(series, "scopeKey", "series")} as series_key
    from ${aliases.completion_authority} as a left join ${aliases.completion_series} as series on true left join ${aliases.completion_continuation} as continuation on true`;

    const decode = Effect.fnUntraced(function* (
      rows: ReadonlyArray<Readonly<Record<string, unknown>>>,
    ) {
      const selectedAuthority = yield* authority.decode(rows);

      const original =
        rows[0] === undefined || rows[0]["completion_continuationId"] === null
          ? undefined
          : yield* decodeSqlRow(continuations, rows[0], "completion_");

      const record =
        original === undefined ? undefined : yield* mapping.continuation.decode(original);

      if (original === undefined || record === undefined)
        return {
          authority: selectedAuthority,
          seriesPresent: rows[0]?.series_key !== null,
          continuation: undefined,
        };

      const consumeCompletion = Effect.gen(function* () {
        yield* sql`update ${t(continuations)} set ${sqlUpdate(sql, continuations, { consumed: true })} where ${c(continuations, "moduleId")} = ${input.moduleId} and ${c(continuations, "continuationId")} = ${input.continuationId} and ${c(continuations, "digest")} = ${input.continuationDigest} and ${c(continuations, "consumed")} = ${sqlValue(sql, continuations, "consumed", false)}`;
        yield* sql`insert into ${t(commands)} ${sqlInsert(sql, commands, mapping.command.encodeInsert({ moduleId: input.moduleId, commandId: input.continuationDigest, kind: "complete", decision: "completed", retentionUntilMillis: record.expiresAtMillis }))}`;

        const rows =
          yield* sql`select ${projection(continuations, "c", "continuation_")}, ${projection(commands, "r", "command_")} from ${t(continuations)} as c left join ${t(commands)} as r on ${c(commands, "moduleId", "r")} = ${input.moduleId} and ${c(commands, "commandId", "r")} = ${input.continuationDigest} where ${c(continuations, "moduleId", "c")} = ${input.moduleId} and ${c(continuations, "continuationId", "c")} = ${input.continuationId} limit 1`;

        if (rows[0] === undefined) return yield* ProofUnavailable.make({});
        const persisted = yield* decodeSqlRow(continuations, rows[0], "continuation_");
        const command = yield* decodeSqlRow(commands, rows[0], "command_");
        const decoded = yield* mapping.continuation.decode(persisted);

        if (
          !sameProofBinding(decoded.binding, record.binding) ||
          persisted.consumed !== true ||
          [
            "moduleId",
            "purpose",
            "continuationId",
            "digest",
            "proofId",
            "seriesKey",
            "version",
          ].some((key) => persisted[key] !== original[key]) ||
          (yield* instant(persisted.expiresAt)) !== record.expiresAtMillis ||
          (yield* instant(persisted.retentionUntil)) !==
            (yield* instant(original.retentionUntil)) ||
          command.kind !== "complete" ||
          command.decision !== "completed" ||
          (yield* instant(command.retentionUntil)) !== record.expiresAtMillis ||
          record.expiresAtMillis <= DateTime.toEpochMillis(yield* DateTime.now)
        )
          return yield* ProofUnavailable.make({});
      });

      return {
        authority: selectedAuthority,
        seriesPresent: rows[0]?.series_key !== null,
        continuation: { record, consumed: original.consumed !== false, consumeCompletion },
      };
    });

    return { statement, decode };
  });

  const store: ProofStore = {
    readAuthority: (input, locking) =>
      Effect.gen(function* () {
        const query = yield* authorityQuery(input, locking);

        return yield* query.decode(yield* query.statement);
      }),
    lockScopes: (input) =>
      Effect.gen(function* () {
        if (input.entries.length === 0) return;
        yield* sql`insert into ${t(scopes)} ${sqlInsertMany(
          sql,
          scopes,
          input.entries.map((entry) =>
            mapping.rateScope.encodeInsert({
              moduleId: input.moduleId,
              purpose: input.purpose,
              action: input.action,
              scopeKind: entry.kind,
              scopeKey: entry.key,
            }),
          ),
        )} on conflict do nothing`;

        const rows =
          yield* sql`select 1 from ${t(scopes)} where ${c(scopes, "moduleId")} = ${input.moduleId} and ${c(scopes, "purpose")} = ${input.purpose} and ${c(scopes, "action")} = ${input.action} and ${sql.or(input.entries.map((entry) => sql`${c(scopes, "scopeKind")} = ${entry.kind} and ${c(scopes, "scopeKey")} = ${entry.key}`))} order by ${c(scopes, "scopeKind")}, ${c(scopes, "scopeKey")} ${lock()}`;

        if (rows.length !== input.entries.length) return yield* ProofUnavailable.make({});
      }),
    readScopeCounts: (input, now) =>
      Effect.gen(function* () {
        if (input.entries.length === 0) return [];

        const [row] =
          yield* sql`select ${sql.csv(input.entries.map((entry, index) => sql`(select count(*) from (select 1 from ${t(abuse)} where ${c(abuse, "moduleId")} = ${input.moduleId} and ${c(abuse, "purpose")} = ${input.purpose} and ${c(abuse, "action")} = ${input.action} and ${c(abuse, "scopeKind")} = ${entry.kind} and ${c(abuse, "scopeKey")} = ${entry.key} and ${c(abuse, "occurredAt")} >= ${nativeInstant(now - entry.budget.windowMillis)} limit ${entry.budget.limit} ${lock(true)}) as recent_events) as ${sqlName(sql, `scope${index}`)}`))}`;

        return yield* Effect.forEach(input.entries, (_, index) =>
          Schema.decodeEffect(Schema.Natural)(Number(row?.[`scope${index}`])),
        );
      }),
    readSeries: (key, initialVersion) =>
      Effect.gen(function* () {
        if (initialVersion !== undefined)
          yield* sql`insert into ${t(series)} ${sqlInsert(sql, series, mapping.series.encodeInsert({ ...key, version: initialVersion }))} on conflict do nothing`;

        const row = yield* decodeFirst(
          series,
          sql`select ${projection(series)} from ${t(series)} where ${c(series, "moduleId")} = ${key.moduleId} and ${c(series, "purpose")} = ${key.purpose} and ${c(series, "scopeKey")} = ${key.scopeKey} limit 1 ${lock()}`,
        );

        if (row === undefined) return undefined;

        return {
          activeProofId:
            row.activeProofId === null
              ? undefined
              : yield* Schema.decodeUnknownEffect(Schema.String)(row.activeProofId),
          lastIssueAtMillis: yield* optionalInstant(row.lastIssueAt),
        };
      }),
    reserveRequest: (input) =>
      Effect.gen(function* () {
        const read = decodeFirst(
          requests,
          sql`select ${projection(requests)} from ${t(requests)} where ${c(requests, "moduleId")} = ${input.record.moduleId} and ${c(requests, "requestId")} = ${input.record.requestId} limit 1 ${lock()}`,
        );

        let row = yield* read;
        const replay = row !== undefined && (yield* instant(row.retentionUntil)) > input.nowMillis;

        if (!replay) {
          if (row !== undefined)
            yield* sql`delete from ${t(requests)} where ${c(requests, "moduleId")} = ${input.record.moduleId} and ${c(requests, "requestId")} = ${input.record.requestId} and ${c(requests, "retentionUntil")} <= ${nativeInstant(input.nowMillis)}`;
          yield* sql`insert into ${t(requests)} ${sqlInsert(sql, requests, mapping.request.encodeInsert({ record: input.record, createdAtMillis: input.nowMillis, retentionUntilMillis: input.retentionUntilMillis }))} on conflict do nothing`;
          row = yield* read;
        }
        if (row === undefined) return yield* ProofUnavailable.make({});

        return {
          fingerprint: yield* Schema.decodeUnknownEffect(Schema.String)(row.fingerprint),
          proofId: yield* Schema.decodeUnknownEffect(Schema.String)(row.proofId),
          replay,
          receipt: mapping.request.decodeReceipt(row),
        };
      }),
    readGeneration,
    readAttempt: (input) =>
      Effect.gen(function* () {
        const seriesRead = input.includeSeries
          ? yield* store.readSeries({
              moduleId: input.attempt.moduleId,
              purpose: input.attempt.purpose,
              scopeKey: input.seriesKey,
            })
          : undefined;

        const generation = yield* readGeneration(
          input.attempt.moduleId,
          input.attempt.proofId,
          options.locking,
        );

        const command = yield* decodeFirst(
          commands,
          sql`select ${projection(commands)} from ${t(commands)} where ${c(commands, "moduleId")} = ${input.attempt.moduleId} and ${c(commands, "commandId")} = ${input.attempt.continuationId} limit 1 ${lock()}`,
        );

        return {
          series: seriesRead,
          generation,
          command:
            command === undefined
              ? undefined
              : {
                  decision: yield* Schema.decodeUnknownEffect(
                    Schema.Literals(["accepted", "rejected", "completed"]),
                  )(command.decision),
                },
        };
      }),
    readFailureCount: (input) =>
      Effect.gen(function* () {
        const rows =
          yield* sql`select 1 from ${t(failures)} where ${c(failures, "moduleId")} = ${input.moduleId} and ${c(failures, "purpose")} = ${input.purpose} and ${c(failures, "seriesKey")} = ${input.seriesKey} and ${c(failures, "occurredAt")} >= ${nativeInstant(input.nowMillis - input.policy.abuse.attempts.windowMillis)} limit ${input.policy.maximumFailedAttempts} ${lock(true)}`;

        return rows.length;
      }),
    publishGeneration: (input) =>
      Effect.gen(function* () {
        yield* recordScopes(
          {
            moduleId: input.record.moduleId,
            purpose: input.record.purpose,
            action: "issue",
            entries: input.scopes,
          },
          input.record.requestId,
          input.nowMillis,
          input.retentionUntilMillis,
        );
        if (input.previousProofId !== undefined)
          yield* sql`update ${t(generations)} set ${sqlUpdate(sql, generations, { state: "superseded" })} where ${c(generations, "moduleId")} = ${input.record.moduleId} and ${c(generations, "proofId")} = ${input.previousProofId} and ${c(generations, "state")} = ${"active"}`;
        yield* sql`insert into ${t(generations)} ${sqlInsert(sql, generations, mapping.generation.encodeInsert({ record: input.record, seriesKey: input.seriesKey, retentionUntilMillis: input.retentionUntilMillis, state: "active", deliveryState: "new", policy: input.policy }))}`;
        yield* sql`update ${t(series)} set ${sqlUpdate(sql, series, { activeProofId: input.record.proofId, lastIssueAt: nativeInstant(input.nowMillis), version: input.nextSeriesVersion })} where ${c(series, "moduleId")} = ${input.record.moduleId} and ${c(series, "purpose")} = ${input.record.purpose} and ${c(series, "scopeKey")} = ${input.seriesKey}`;
      }),
    recordAttempt: (write) =>
      Effect.gen(function* () {
        const input = write.input;

        yield* sql`insert into ${t(commands)} ${sqlInsert(sql, commands, mapping.command.encodeInsert({ moduleId: input.moduleId, commandId: input.continuationId, kind: "attempt", decision: write.decision, retentionUntilMillis: write.retentionUntilMillis }))}`;
        yield* recordScopes(
          { ...input, action: "attempt", entries: write.scopes },
          input.continuationId,
          write.nowMillis,
          write.retentionUntilMillis,
        );
        if (write.decision === "rejected") {
          if (write.recordFailure)
            yield* sql`insert into ${t(failures)} ${sqlInsert(sql, failures, mapping.failureEvent.encodeInsert({ moduleId: input.moduleId, purpose: input.purpose, seriesKey: write.seriesKey, commandId: input.continuationId, occurredAtMillis: write.nowMillis, retentionUntilMillis: write.retentionUntilMillis }))}`;
        } else {
          yield* sql`update ${t(generations)} set ${sqlUpdate(sql, generations, { state: "consumed" })} where ${c(generations, "moduleId")} = ${input.moduleId} and ${c(generations, "proofId")} = ${input.proofId} and ${c(generations, "state")} = ${"active"}`;
          yield* sql`insert into ${t(continuations)} ${sqlInsert(sql, continuations, mapping.continuation.encodeInsert({ ...write.continuation, retentionUntilMillis: write.retentionUntilMillis }))}`;
        }
      }),
    readCompletion: (input, mutating) =>
      Effect.gen(function* () {
        const query = yield* completionQuery(input, mutating);

        return yield* query.decode(yield* query.statement);
      }),
    readDeliverySettlement: (input) =>
      Effect.gen(function* () {
        if (input.outcome._tag === "DefiniteFailure") {
          const initial = yield* readGeneration(input.moduleId, input.proofId, false);

          if (initial === undefined) return undefined;

          const key = {
            moduleId: input.moduleId,
            purpose: yield* Schema.decodeEffect(ProofPurpose)(initial.purpose),
            scopeKey: initial.seriesKey,
          };

          if (
            (yield* store.readSeries(key, yield* allocateProofVersion(mapping, options.mode))) ===
            undefined
          )
            return yield* ProofUnavailable.make({});
        }

        return yield* readGeneration(input.moduleId, input.proofId, options.locking);
      }),
    writeDelivery: (input) =>
      Effect.gen(function* () {
        if (input.transition === "ExpiredClaim") {
          yield* sql`update ${t(generations)} set ${sqlUpdate(sql, generations, { deliveryState: "ambiguous" })} where ${c(generations, "moduleId")} = ${input.moduleId} and ${c(generations, "proofId")} = ${input.proofId}`;
        } else if (input.transition === "Claim") {
          yield* sql`update ${t(generations)} set ${sqlUpdate(sql, generations, { sendCount: input.sendCount, deliveryState: "claimed", claimVersion: input.claimVersion, claimDeadline: nativeInstant(input.claimDeadlineMillis), retryAt: nativeInstant(input.retryAtMillis) })} where ${c(generations, "moduleId")} = ${input.moduleId} and ${c(generations, "proofId")} = ${input.proofId}`;
        } else {
          const g = input.generation;

          yield* sql`update ${t(generations)} set ${sqlUpdate(sql, generations, { deliveryState: input.state, claimDeadline: null, ...(input.retryAtMillis === undefined ? {} : { retryAt: nativeInstant(input.retryAtMillis) }), ...(input.state === "failed" ? { state: "cancelled" } : {}) })} where ${c(generations, "moduleId")} = ${g.moduleId} and ${c(generations, "proofId")} = ${g.proofId}`;
          if (input.state === "failed")
            yield* sql`update ${t(series)} set ${sqlUpdate(sql, series, { activeProofId: null })} where ${c(series, "moduleId")} = ${g.moduleId} and ${c(series, "purpose")} = ${g.purpose} and ${c(series, "scopeKey")} = ${g.seriesKey} and ${c(series, "activeProofId")} = ${g.proofId}`;
        }
      }),
    cancelGeneration: (key, proofId) =>
      Effect.gen(function* () {
        yield* sql`update ${t(generations)} set ${sqlUpdate(sql, generations, { state: "cancelled" })} where ${c(generations, "moduleId")} = ${key.moduleId} and ${c(generations, "proofId")} = ${proofId}`;
        yield* sql`update ${t(series)} set ${sqlUpdate(sql, series, { activeProofId: null })} where ${c(series, "moduleId")} = ${key.moduleId} and ${c(series, "purpose")} = ${key.purpose} and ${c(series, "scopeKey")} = ${key.scopeKey} and ${c(series, "activeProofId")} = ${proofId}`;
      }),
    readExpired: (input) =>
      Effect.gen(function* () {
        const cutoff = nativeInstant(input.nowMillis);
        let remaining = input.limit;
        let hasMore = false;

        const take = (query: Fragment) =>
          sql`${query} limit ${remaining + 1} ${lock()}`.pipe(
            Effect.map((rows) => {
              if (rows.length > remaining) hasMore = true;
              const page = rows.slice(0, remaining);

              remaining -= page.length;

              return page;
            }),
          );

        const expiredContinuations = yield* take(
          sql`select ${c(continuations, "continuationId")} as id from ${t(continuations)} where ${c(continuations, "moduleId")} = ${input.moduleId} and ${c(continuations, "retentionUntil")} <= ${cutoff} order by ${c(continuations, "retentionUntil")}, ${c(continuations, "continuationId")}`,
        );

        const expiredGenerations = yield* take(
          sql`select ${c(generations, "proofId")} as id from ${t(generations)} where ${c(generations, "moduleId")} = ${input.moduleId} and ${c(generations, "retentionUntil")} <= ${cutoff} order by ${c(generations, "retentionUntil")}, ${c(generations, "proofId")}`,
        );

        const expiredRequests = yield* take(
          sql`select ${c(requests, "requestId")} as id from ${t(requests)} where ${c(requests, "moduleId")} = ${input.moduleId} and ${c(requests, "retentionUntil")} <= ${cutoff} order by ${c(requests, "retentionUntil")}, ${c(requests, "requestId")}`,
        );

        const expiredAbuse = yield* take(
          sql`select ${c(abuse, "action")} as action, ${c(abuse, "scopeKind")} as kind, ${c(abuse, "scopeKey")} as key, ${c(abuse, "commandId")} as id from ${t(abuse)} where ${c(abuse, "moduleId")} = ${input.moduleId} and ${c(abuse, "retentionUntil")} <= ${cutoff} order by ${c(abuse, "retentionUntil")}, ${c(abuse, "action")}, ${c(abuse, "scopeKind")}, ${c(abuse, "scopeKey")}, ${c(abuse, "commandId")}`,
        );

        const expiredFailures = yield* take(
          sql`select ${c(failures, "seriesKey")} as key, ${c(failures, "commandId")} as id from ${t(failures)} where ${c(failures, "moduleId")} = ${input.moduleId} and ${c(failures, "retentionUntil")} <= ${cutoff} order by ${c(failures, "retentionUntil")}, ${c(failures, "seriesKey")}, ${c(failures, "commandId")}`,
        );

        const expiredCommands = yield* take(
          sql`select ${c(commands, "commandId")} as id from ${t(commands)} where ${c(commands, "moduleId")} = ${input.moduleId} and ${c(commands, "retentionUntil")} <= ${cutoff} order by ${c(commands, "retentionUntil")}, ${c(commands, "commandId")}`,
        );

        const emptySeries = sql`${c(series, "activeProofId")} is null and not exists (select 1 from ${t(generations)} where ${c(generations, "moduleId")} = ${c(series, "moduleId")} and ${c(generations, "purpose")} = ${c(series, "purpose")} and ${c(generations, "seriesKey")} = ${c(series, "scopeKey")}) and not exists (select 1 from ${t(failures)} where ${c(failures, "moduleId")} = ${c(series, "moduleId")} and ${c(failures, "purpose")} = ${c(series, "purpose")} and ${c(failures, "seriesKey")} = ${c(series, "scopeKey")})`;

        const expiredSeries = yield* take(
          sql`select ${c(series, "purpose")} as purpose, ${c(series, "scopeKey")} as key from ${t(series)} where ${c(series, "moduleId")} = ${input.moduleId} and ${emptySeries} order by ${c(series, "purpose")}, ${c(series, "scopeKey")}`,
        );

        const emptyScope = sql`not exists (select 1 from ${t(abuse)} where ${c(abuse, "moduleId")} = ${c(scopes, "moduleId")} and ${c(abuse, "purpose")} = ${c(scopes, "purpose")} and ${c(abuse, "action")} = ${c(scopes, "action")} and ${c(abuse, "scopeKind")} = ${c(scopes, "scopeKind")} and ${c(abuse, "scopeKey")} = ${c(scopes, "scopeKey")})`;

        const expiredScopes = yield* take(
          sql`select ${c(scopes, "purpose")} as purpose, ${c(scopes, "action")} as action, ${c(scopes, "scopeKind")} as kind, ${c(scopes, "scopeKey")} as key from ${t(scopes)} where ${c(scopes, "moduleId")} = ${input.moduleId} and ${emptyScope} order by ${c(scopes, "purpose")}, ${c(scopes, "action")}, ${c(scopes, "scopeKind")}, ${c(scopes, "scopeKey")}`,
        );

        hasMore ||=
          expiredGenerations.length > 0 || expiredFailures.length > 0 || expiredAbuse.length > 0;

        const relation = (payload: string) =>
          sql.onDialectOrElse({
            pg: () => sql`jsonb_array_elements(cast(${payload} as jsonb)) as cleanup(value)`,
            orElse: () => sql`json_each(${payload}) as cleanup`,
          });

        const field = (key: "purpose" | "action" | "kind" | "key" | "id") =>
          sql.onDialectOrElse({
            pg: () => sql`cleanup.value ->> ${key}`,
            orElse: () => sql`json_extract(cleanup.value, ${"$." + key})`,
          });

        const ids = (payload: string) => sql`(select ${field("id")} from ${relation(payload)})`;

        const deleteExpired = Effect.gen(function* () {
          for (const batch of yield* jsonBatches(expiredContinuations))
            yield* sql`delete from ${t(continuations)} where ${c(continuations, "moduleId")} = ${input.moduleId} and ${c(continuations, "continuationId")} in ${ids(batch.payload)} and ${c(continuations, "retentionUntil")} <= ${cutoff}`;
          for (const batch of yield* jsonBatches(expiredGenerations)) {
            yield* sql`update ${t(series)} set ${sqlUpdate(sql, series, { activeProofId: null })} where ${c(series, "moduleId")} = ${input.moduleId} and ${c(series, "activeProofId")} in ${ids(batch.payload)}`;
            yield* sql`delete from ${t(generations)} where ${c(generations, "moduleId")} = ${input.moduleId} and ${c(generations, "proofId")} in ${ids(batch.payload)} and ${c(generations, "retentionUntil")} <= ${cutoff}`;
          }
          for (const batch of yield* jsonBatches(expiredRequests))
            yield* sql`delete from ${t(requests)} where ${c(requests, "moduleId")} = ${input.moduleId} and ${c(requests, "requestId")} in ${ids(batch.payload)} and ${c(requests, "retentionUntil")} <= ${cutoff}`;
          for (const batch of yield* jsonBatches(expiredAbuse))
            yield* sql`delete from ${t(abuse)} where ${c(abuse, "moduleId")} = ${input.moduleId} and (${c(abuse, "action")}, ${c(abuse, "scopeKind")}, ${c(abuse, "scopeKey")}, ${c(abuse, "commandId")}) in (select ${field("action")}, ${field("kind")}, ${field("key")}, ${field("id")} from ${relation(batch.payload)}) and ${c(abuse, "retentionUntil")} <= ${cutoff}`;
          for (const batch of yield* jsonBatches(expiredFailures))
            yield* sql`delete from ${t(failures)} where ${c(failures, "moduleId")} = ${input.moduleId} and (${c(failures, "seriesKey")}, ${c(failures, "commandId")}) in (select ${field("key")}, ${field("id")} from ${relation(batch.payload)}) and ${c(failures, "retentionUntil")} <= ${cutoff}`;
          for (const batch of yield* jsonBatches(expiredCommands))
            yield* sql`delete from ${t(commands)} where ${c(commands, "moduleId")} = ${input.moduleId} and ${c(commands, "commandId")} in ${ids(batch.payload)} and ${c(commands, "retentionUntil")} <= ${cutoff}`;
          for (const batch of yield* jsonBatches(expiredSeries))
            yield* sql`delete from ${t(series)} where ${c(series, "moduleId")} = ${input.moduleId} and (${c(series, "purpose")}, ${c(series, "scopeKey")}) in (select ${field("purpose")}, ${field("key")} from ${relation(batch.payload)}) and ${emptySeries}`;
          for (const batch of yield* jsonBatches(expiredScopes))
            yield* sql`delete from ${t(scopes)} where ${c(scopes, "moduleId")} = ${input.moduleId} and (${c(scopes, "purpose")}, ${c(scopes, "action")}, ${c(scopes, "scopeKind")}, ${c(scopes, "scopeKey")}) in (select ${field("purpose")}, ${field("action")}, ${field("kind")}, ${field("key")} from ${relation(batch.payload)}) and ${emptyScope}`;
        });

        return { result: { removed: input.limit - remaining, hasMore }, deleteExpired };
      }),
  };

  return {
    completionQuery,
    read: store,
    transaction: <A, E, R>(body: (store: ProofStore) => Effect.Effect<A, E, R>) =>
      sql.withTransaction(body(store)),
  };
};
