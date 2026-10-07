import { allocateProofVersion } from "@yielded/auth-persistence/Adapter";
import {
  type AnyProofPersistenceMapping,
  type ProofAction,
  type ProofCommandDecision,
  type ProofScopeKind,
} from "@yielded/auth-persistence/Adapter";
import {
  type ProofBinding,
  ProofUnavailable,
  type ProofPolicy,
  type ProofBudget,
} from "@yielded/auth/Proofs";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { and, eq, gte, inArray, or, sql } from "drizzle-orm";
import { DateTime, Effect, Schema } from "effect";

import { column } from "./model";
import type { NativeSqlDatabase, NativeSqlQuery } from "./native-database";
import { CurrentProofSql, type ProofSqlConfiguration } from "./proof-database";
import { readSnapshot as readSnapshots, type SnapshotRead } from "./sql-snapshot";
/* oxlint-disable no-explicit-any -- mapping codecs retain native row types; query helpers do not decide application policy. */
export type Mapping = AnyProofPersistenceMapping;
type Database = NativeSqlDatabase;

export interface ScopeEntry {
  readonly kind: ProofScopeKind;
  readonly key: string;
  readonly budget: ProofBudget;
}

const unavailable = () => ProofUnavailable.make({});

export const selectRows = (query: NativeSqlQuery, locking: boolean) =>
  locking && typeof query.for === "function" ? query.for("update") : query;

// Admission has at most three scopes. Preserve application column defaults
// when an encoder returns different shapes for different scope kinds.
export const insertScopeRows = Effect.fn("DrizzleProof.insertScopeRows")(function* (
  query: NativeSqlQuery,
  rows: ReadonlyArray<Record<string, unknown>>,
  prepare: (query: NativeSqlQuery) => NativeSqlQuery = (query) => query,
) {
  const first = rows[0];

  if (first === undefined) return;

  const fields = (row: Record<string, unknown>) =>
    Object.keys(row)
      .filter((key) => row[key] !== undefined)
      .sort()
      .join("\0");

  const shape = fields(first);
  const batches = rows.every((row) => fields(row) === shape) ? [rows] : rows.map((row) => [row]);

  for (const batch of batches) yield* prepare(query.values(batch));
});

export const requestColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.request.table, mapping.request.moduleId),
  requestId: column(mapping.request.table, mapping.request.requestId),
  fingerprint: column(mapping.request.table, mapping.request.fingerprint),
  proofId: column(mapping.request.table, mapping.request.proofId),
  retentionUntil: column(mapping.request.table, mapping.request.retentionUntil),
});

export const seriesColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.series.table, mapping.series.moduleId),
  purpose: column(mapping.series.table, mapping.series.purpose),
  scopeKey: column(mapping.series.table, mapping.series.scopeKey),
  activeProofId: column(mapping.series.table, mapping.series.activeProofId),
  lastIssueAt: column(mapping.series.table, mapping.series.lastIssueAt),
  version: column(mapping.series.table, mapping.series.version),
});

export const generationColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.generation.table, mapping.generation.moduleId),
  purpose: column(mapping.generation.table, mapping.generation.purpose),
  proofId: column(mapping.generation.table, mapping.generation.proofId),
  requestId: column(mapping.generation.table, mapping.generation.requestId),
  seriesKey: column(mapping.generation.table, mapping.generation.seriesKey),
  deliveryId: column(mapping.generation.table, mapping.generation.deliveryId),
  verifierKeyId: column(mapping.generation.table, mapping.generation.verifierKeyId),
  verifierDigest: column(mapping.generation.table, mapping.generation.verifierDigest),
  issuedAt: column(mapping.generation.table, mapping.generation.issuedAt),
  expiresAt: column(mapping.generation.table, mapping.generation.expiresAt),
  version: column(mapping.generation.table, mapping.generation.version),
  state: column(mapping.generation.table, mapping.generation.state),
  sendCount: column(mapping.generation.table, mapping.generation.sendCount),
  deliveryState: column(mapping.generation.table, mapping.generation.deliveryState),
  claimVersion: column(mapping.generation.table, mapping.generation.claimVersion),
  claimDeadline: column(mapping.generation.table, mapping.generation.claimDeadline),
  retryAt: column(mapping.generation.table, mapping.generation.retryAt),
  deliveryRetryMillis: column(mapping.generation.table, mapping.generation.deliveryRetryMillis),
  retentionUntil: column(mapping.generation.table, mapping.generation.retentionUntil),
});

export const continuationColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.continuation.table, mapping.continuation.moduleId),
  purpose: column(mapping.continuation.table, mapping.continuation.purpose),
  continuationId: column(mapping.continuation.table, mapping.continuation.continuationId),
  digest: column(mapping.continuation.table, mapping.continuation.digest),
  proofId: column(mapping.continuation.table, mapping.continuation.proofId),
  seriesKey: column(mapping.continuation.table, mapping.continuation.seriesKey),
  expiresAt: column(mapping.continuation.table, mapping.continuation.expiresAt),
  consumed: column(mapping.continuation.table, mapping.continuation.consumed),
  version: column(mapping.continuation.table, mapping.continuation.version),
  retentionUntil: column(mapping.continuation.table, mapping.continuation.retentionUntil),
});

export const scopeColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.rateScope.table, mapping.rateScope.moduleId),
  purpose: column(mapping.rateScope.table, mapping.rateScope.purpose),
  action: column(mapping.rateScope.table, mapping.rateScope.action),
  scopeKind: column(mapping.rateScope.table, mapping.rateScope.scopeKind),
  scopeKey: column(mapping.rateScope.table, mapping.rateScope.scopeKey),
});

export const abuseColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.abuseEvent.table, mapping.abuseEvent.moduleId),
  purpose: column(mapping.abuseEvent.table, mapping.abuseEvent.purpose),
  action: column(mapping.abuseEvent.table, mapping.abuseEvent.action),
  scopeKind: column(mapping.abuseEvent.table, mapping.abuseEvent.scopeKind),
  scopeKey: column(mapping.abuseEvent.table, mapping.abuseEvent.scopeKey),
  commandId: column(mapping.abuseEvent.table, mapping.abuseEvent.commandId),
  occurredAt: column(mapping.abuseEvent.table, mapping.abuseEvent.occurredAt),
  retentionUntil: column(mapping.abuseEvent.table, mapping.abuseEvent.retentionUntil),
});

export const failureColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.failureEvent.table, mapping.failureEvent.moduleId),
  purpose: column(mapping.failureEvent.table, mapping.failureEvent.purpose),
  seriesKey: column(mapping.failureEvent.table, mapping.failureEvent.seriesKey),
  commandId: column(mapping.failureEvent.table, mapping.failureEvent.commandId),
  occurredAt: column(mapping.failureEvent.table, mapping.failureEvent.occurredAt),
  retentionUntil: column(mapping.failureEvent.table, mapping.failureEvent.retentionUntil),
});

export const commandColumns = (mapping: Mapping) => ({
  moduleId: column(mapping.command.table, mapping.command.moduleId),
  commandId: column(mapping.command.table, mapping.command.commandId),
  kind: column(mapping.command.table, mapping.command.kind),
  decision: column(mapping.command.table, mapping.command.decision),
  retentionUntil: column(mapping.command.table, mapping.command.retentionUntil),
});

export const nowMillis = DateTime.now.pipe(Effect.map(DateTime.toEpochMillis));

type SnapshotRows = ReadonlyArray<ReadonlyArray<Record<string, any>>>;

export const readRows = Effect.fnUntraced(function* (
  database: Database,
  reads: ReadonlyArray<SnapshotRead>,
  configuration: ProofSqlConfiguration,
) {
  if (!configuration.locking || configuration.pgOrderedLocks)
    return yield* readSnapshots(
      database,
      reads,
      configuration.maxParameters,
      configuration.pgOrderedLocks,
    ).rows;

  return yield* Effect.forEach(reads, (read) => {
    let query = database.select().from(read.table).where(read.where);

    if (read.limit !== undefined) query = query.limit(read.limit);
    if (read.orderBy !== undefined) query = query.orderBy(...read.orderBy);

    return selectRows(query, configuration.locking);
  });
});

export const authorityRead = Effect.fnUntraced(function* (
  mapping: Mapping,
  moduleId: string,
  purpose: any,
  binding: ProofBinding,
) {
  const authority = mapping.authority;
  const reads: SnapshotRead[] = [];
  let nativeSubjectId: unknown;

  if (binding._tag !== "Identifier") {
    if (
      authority.subject === undefined ||
      authority.credential === undefined ||
      authority.subjectId === undefined
    )
      return yield* unavailable();
    nativeSubjectId = yield* authority.subjectId.toNative(binding.revision.subjectId);
    const subject = authority.subject;

    reads.push({
      table: subject.table,
      where: eq(column(subject.table, subject.id), nativeSubjectId),
      limit: 1,
    });
  }
  const identifier = authority.identifier;
  const identifierIndex = reads.length;

  reads.push({
    table: identifier.table,
    where: and(
      eq(column(identifier.table, identifier.namespace), binding.identifier.namespace),
      eq(column(identifier.table, identifier.value), binding.identifier.value),
    ),
  });

  const expected =
    binding._tag === "Identifier"
      ? []
      : [...binding.revision.credentials].sort((a, b) =>
          a.credentialId.localeCompare(b.credentialId),
        );

  const credentialIndex = reads.length;

  if (expected.length !== 0) {
    const credential = authority.credential!;

    reads.push({
      table: credential.table,
      where: and(
        eq(column(credential.table, credential.subjectId), nativeSubjectId),
        inArray(
          column(credential.table, credential.credentialId),
          expected.map((item) => item.credentialId),
        ),
      ),
      orderBy: [column(credential.table, credential.credentialId)],
    });
  }

  return {
    reads,
    facts: (rows: SnapshotRows) =>
      Effect.gen(function* () {
        const subject = authority.subject;
        const subjectRow = binding._tag === "Identifier" ? undefined : rows[0]?.[0];
        const credential = authority.credential;
        const credentials = expected.length === 0 ? [] : (rows[credentialIndex] ?? []);

        return {
          subject:
            subject === undefined || subjectRow === undefined
              ? undefined
              : {
                  active: subject.isActiveStatus(subjectRow[subject.status]),
                  securityRevision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
                    subjectRow[subject.securityRevision],
                  ),
                },
          identifierCurrent: identifier.isCurrent(
            {
              moduleId,
              purpose,
              binding,
              ...(nativeSubjectId === undefined ? {} : { nativeSubjectId }),
            },
            rows[identifierIndex] ?? [],
          ),
          credentials:
            credential === undefined
              ? []
              : yield* Effect.forEach(credentials, (row) =>
                  Effect.gen(function* () {
                    return {
                      credentialId: yield* Schema.decodeUnknownEffect(Schema.String)(
                        row[credential.credentialId],
                      ),
                      revision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
                        row[credential.revision],
                      ),
                      active:
                        credential.status === undefined ||
                        credential.isActiveStatus?.(row[credential.status]) === true,
                    };
                  }),
                ),
        };
      }),
  };
});

export const lockScopes = Effect.fn("DrizzleProof.lockScopes")(function* (
  mapping: Mapping,
  configuration: ProofSqlConfiguration,
  moduleId: string,
  purpose: any,
  action: ProofAction,
  entries: ReadonlyArray<ScopeEntry>,
) {
  const database = yield* CurrentProofSql;
  const c = scopeColumns(mapping);

  // The global anchor is a separate first phase. VALUES and the lock read use
  // canonical scope order. moduleId is a shared no-op conflict value on MySQL.
  yield* insertScopeRows(
    database.insert(mapping.rateScope.table),
    entries.map((entry) =>
      mapping.rateScope.encodeInsert({
        moduleId,
        purpose,
        action,
        scopeKind: entry.kind,
        scopeKey: entry.key,
      }),
    ),
    (query) => configuration.insertIfAbsent(query, mapping.rateScope.moduleId, moduleId),
  );

  const locked = yield* selectRows(
    database
      .select({ scopeKind: c.scopeKind, scopeKey: c.scopeKey })
      .from(mapping.rateScope.table)
      .where(
        and(
          eq(c.moduleId, moduleId),
          eq(c.purpose, purpose),
          eq(c.action, action),
          or(
            ...entries.map((entry) => and(eq(c.scopeKind, entry.kind), eq(c.scopeKey, entry.key))),
          ),
        ),
      )
      .orderBy(c.scopeKind, c.scopeKey),
    configuration.locking,
  );

  if (locked.length !== entries.length) return yield* unavailable();
});

export const scopeCounts = Effect.fn("DrizzleProof.admittedScopes")(function* (
  mapping: Mapping,
  moduleId: string,
  purpose: any,
  action: ProofAction,
  entries: ReadonlyArray<ScopeEntry>,
  now: number,
) {
  if (entries.length === 0) return [];
  const database = yield* CurrentProofSql;
  const c = abuseColumns(mapping);

  // Each scalar scan stays bounded by its own budget and keeps its locking
  // read. One statement returns counts without transferring every event row.
  const [counts] = yield* database
    .select(
      Object.fromEntries(
        entries.map((entry, index) => {
          const query = selectRows(
            database
              .select({ commandId: c.commandId })
              .from(mapping.abuseEvent.table)
              .where(
                and(
                  eq(c.moduleId, moduleId),
                  eq(c.purpose, purpose),
                  eq(c.action, action),
                  eq(c.scopeKind, entry.kind),
                  eq(c.scopeKey, entry.key),
                  gte(c.occurredAt, mapping.encodeInstant(now - entry.budget.windowMillis)),
                ),
              )
              .limit(entry.budget.limit),
            true,
          );

          return [
            `scope${index}`,
            sql`(select count(*) from (${query.getSQL()}) as proof_events)`.mapWith(Number),
          ];
        }),
      ),
    )
    .from(sql`(select 1) as proof_admission`);

  return entries.map((_, index) => Number(counts?.[`scope${index}`]));
});

export const insertScopeEvents = Effect.fn("Drizzle.insertScopeEvents")(function* (
  mapping: Mapping,
  moduleId: string,
  purpose: any,
  action: ProofAction,
  commandId: string,
  entries: ReadonlyArray<ScopeEntry>,
  now: number,
  retentionUntil: number,
) {
  const database = yield* CurrentProofSql;

  yield* insertScopeRows(
    database.insert(mapping.abuseEvent.table),
    entries.map((entry) =>
      mapping.abuseEvent.encodeInsert({
        moduleId,
        purpose,
        action,
        scopeKind: entry.kind,
        scopeKey: entry.key,
        commandId,
        occurredAtMillis: now,
        retentionUntilMillis: retentionUntil,
      }),
    ),
  );
});

export const readSeries = Effect.fnUntraced(function* (
  mapping: Mapping,
  configuration: ProofSqlConfiguration,
  moduleId: string,
  purpose: any,
  scopeKey: string,
) {
  const database = yield* CurrentProofSql;
  const c = seriesColumns(mapping);

  const rows = yield* selectRows(
    database
      .select()
      .from(mapping.series.table)
      .where(and(eq(c.moduleId, moduleId), eq(c.purpose, purpose), eq(c.scopeKey, scopeKey)))
      .limit(1),
    configuration.locking,
  );

  return rows[0];
});

export const ensureSeries = Effect.fn("DrizzleProof.ensureSeries")(function* (
  mapping: Mapping,
  configuration: ProofSqlConfiguration,
  moduleId: string,
  purpose: any,
  scopeKey: string,
) {
  const database = yield* CurrentProofSql;

  const initialVersion = yield* allocateProofVersion(mapping, configuration.mode);

  const query = database
    .insert(mapping.series.table)
    .values(mapping.series.encodeInsert({ moduleId, purpose, scopeKey, version: initialVersion }));

  yield* configuration.insertIfAbsent(query, mapping.series.scopeKey, scopeKey);

  return (
    (yield* readSeries(mapping, configuration, moduleId, purpose, scopeKey)) ??
    (yield* unavailable())
  );
});

export const readGeneration = Effect.fn("Drizzle.readGeneration")(function* (
  mapping: Mapping,
  moduleId: string,
  proofId: string,
  locking: boolean,
) {
  const database = yield* CurrentProofSql;

  const c = generationColumns(mapping);

  return yield* selectRows(
    database
      .select()
      .from(mapping.generation.table)
      .where(and(eq(c.moduleId, moduleId), eq(c.proofId, proofId)))
      .limit(1),
    locking,
  );
});

export const failureCount = Effect.fn("DrizzleProof.failureCount")(function* (
  mapping: Mapping,
  moduleId: string,
  purpose: any,
  seriesKey: string,
  now: number,
  policy: ProofPolicy,
) {
  const database = yield* CurrentProofSql;

  const c = failureColumns(mapping);

  const rows = yield* selectRows(
    database
      .select({ commandId: c.commandId })
      .from(mapping.failureEvent.table)
      .where(
        and(
          eq(c.moduleId, moduleId),
          eq(c.purpose, purpose),
          eq(c.seriesKey, seriesKey),
          gte(c.occurredAt, mapping.encodeInstant(now - policy.abuse.attempts.windowMillis)),
        ),
      )
      .limit(policy.maximumFailedAttempts),
    true,
  );

  return rows.length;
});

export const commandRow = Effect.fn("Drizzle.commandRow")(function* (
  mapping: Mapping,
  moduleId: string,
  commandId: string,
  locking: boolean,
) {
  const database = yield* CurrentProofSql;

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
  moduleId: string,
  commandId: string,
  kind: "attempt" | "complete",
  decision: ProofCommandDecision,
  retentionUntil: number,
) {
  const database = yield* CurrentProofSql;

  return yield* database.insert(mapping.command.table).values(
    mapping.command.encodeInsert({
      moduleId,
      commandId,
      kind,
      decision,
      retentionUntilMillis: retentionUntil,
    }),
  );
});
