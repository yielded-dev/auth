import {
  type ProofStore,
  type ProofWorkflowOptions,
  type ProofStoreError,
  type ProofGenerationRead,
  type ProofSeriesRead,
  type ProofCompletionRead,
  type ProofCompletionStore,
  type PersistenceOwner,
  CurrentProofStore,
  sameProofBinding,
  translateProofFailure,
} from "@yielded/auth-persistence/Adapter";
import { ProofUnavailable, type ProofCompletionPlan } from "@yielded/auth/Proofs";
import { and, eq, lte } from "drizzle-orm";
import { Effect, Option, Schema } from "effect";

import { updateValues } from "./model";
import { CurrentMutationTransaction, MutationPostconditions } from "./mutation-postconditions";
import { NativeDatabase } from "./native-database";
import type { NativeSqlDatabase } from "./native-database";
import { readExpiredProofs } from "./proof-cleanup";
import { CurrentProofSql, type ProofSqlConfiguration } from "./proof-database";
import * as N from "./proof-native";
import { readSnapshot, type SnapshotRead } from "./sql-snapshot";

/* oxlint-disable no-explicit-any -- native mappings erase foreign row shapes; facts use mapped decoders and schemas. */
type Row = Record<string, any>;
const unavailable = () => ProofUnavailable.make({});
const text = Schema.decodeUnknownEffect(Schema.String);

const generationState = Schema.decodeUnknownEffect(
  Schema.Literals(["active", "consumed", "cancelled", "superseded"]),
);

const deliveryState = Schema.decodeUnknownEffect(
  Schema.Literals(["new", "claimed", "accepted", "failed", "ambiguous"]),
);

const commandDecision = Schema.decodeUnknownEffect(
  Schema.Literals(["accepted", "rejected", "completed"]),
);

const nullable = <A, E>(value: unknown, decode: (value: unknown) => Effect.Effect<A, E>) =>
  value === null || value === undefined ? Effect.succeed(undefined) : decode(value);

const decodeSeries = (
  mapping: N.Mapping,
  row: Row | undefined,
): Effect.Effect<ProofSeriesRead | undefined, ProofStoreError> =>
  Effect.gen(function* () {
    if (row === undefined) return undefined;

    return {
      activeProofId: yield* nullable(row[mapping.series.activeProofId], text),
      lastIssueAtMillis: yield* nullable(row[mapping.series.lastIssueAt], mapping.decodeInstant),
    };
  });

const decodeGeneration = (
  mapping: N.Mapping,
  row: Row | undefined,
): Effect.Effect<ProofGenerationRead | undefined, ProofStoreError> =>
  Effect.gen(function* () {
    if (row === undefined) return undefined;
    const c = mapping.generation;

    return {
      moduleId: yield* text(row[c.moduleId]),
      purpose: yield* text(row[c.purpose]),
      proofId: yield* text(row[c.proofId]),
      seriesKey: yield* text(row[c.seriesKey]),
      version: yield* text(row[c.version]),
      deliveryId: yield* text(row[c.deliveryId]),
      verifierKeyId: yield* text(row[c.verifierKeyId]),
      verifierDigest: yield* text(row[c.verifierDigest]),
      expiresAtMillis: yield* mapping.decodeInstant(row[c.expiresAt]),
      state: yield* generationState(row[c.state]),
      binding: mapping.generation.decodeBinding(row),
      sendCount: Number(row[c.sendCount]),
      deliveryState: yield* deliveryState(row[c.deliveryState]),
      claimVersion: yield* nullable(row[c.claimVersion], text),
      claimDeadlineMillis: yield* nullable(row[c.claimDeadline], mapping.decodeInstant),
      retryAtMillis: yield* nullable(row[c.retryAt], mapping.decodeInstant),
      deliveryRetryMillis: Number(row[c.deliveryRetryMillis]),
    };
  });

/** An accepted completion retains this operation's own preimage. Its deferred
 * check resolves the final parent transaction when executed after application work. */
const consumeCompletion = (
  mapping: N.Mapping,
  configuration: ProofSqlConfiguration,
  database: NativeSqlDatabase,
  input: ProofCompletionPlan["input"],
  original: Row,
  record: NonNullable<ProofCompletionRead["continuation"]>["record"],
): Effect.Effect<void, ProofStoreError> =>
  Effect.gen(function* () {
    const c = N.continuationColumns(mapping);

    yield* database
      .update(mapping.continuation.table)
      .set(updateValues([[mapping.continuation.consumed, true]]))
      .where(
        and(
          eq(c.moduleId, input.moduleId),
          eq(c.continuationId, input.continuationId),
          eq(c.digest, input.continuationDigest),
          eq(c.consumed, false),
        ),
      );
    yield* N.insertCommand(
      mapping,
      input.moduleId,
      input.continuationDigest,
      "complete",
      "completed",
      record.expiresAtMillis,
    ).pipe(Effect.provideService(CurrentProofSql, database));

    const assertApplied = Effect.flatMap(CurrentMutationTransaction, (current) =>
      Effect.gen(function* () {
        const mc = N.commandColumns(mapping);

        const [continuations, commands] = yield* readSnapshot(
          current,
          [
            {
              table: mapping.continuation.table,
              where: and(
                eq(c.moduleId, input.moduleId),
                eq(c.continuationId, input.continuationId),
              ),
              limit: 1,
            },
            {
              table: mapping.command.table,
              where: and(
                eq(mc.moduleId, input.moduleId),
                eq(mc.commandId, input.continuationDigest),
              ),
              limit: 1,
            },
          ],
          configuration.maxParameters,
        ).rows;

        const persisted = continuations?.[0],
          command = commands?.[0];

        const decoded =
          persisted === undefined ? undefined : yield* mapping.continuation.decode(persisted);

        const immutable = [
          mapping.continuation.moduleId,
          mapping.continuation.purpose,
          mapping.continuation.continuationId,
          mapping.continuation.digest,
          mapping.continuation.proofId,
          mapping.continuation.seriesKey,
          mapping.continuation.version,
        ];

        if (
          persisted === undefined ||
          decoded === undefined ||
          !sameProofBinding(decoded.binding, record.binding) ||
          persisted[mapping.continuation.consumed] !== true ||
          immutable.some((key) => persisted[key] !== original[key]) ||
          (yield* mapping.decodeInstant(persisted[mapping.continuation.expiresAt])) !==
            record.expiresAtMillis ||
          (yield* mapping.decodeInstant(persisted[mapping.continuation.retentionUntil])) !==
            (yield* mapping.decodeInstant(original[mapping.continuation.retentionUntil])) ||
          command === undefined ||
          command[mapping.command.kind] !== "complete" ||
          command[mapping.command.decision] !== "completed" ||
          (yield* mapping.decodeInstant(command[mapping.command.retentionUntil])) !==
            record.expiresAtMillis ||
          record.expiresAtMillis <= (yield* N.nowMillis)
        )
          return yield* unavailable();
      }),
    );

    yield* assertApplied.pipe(Effect.provideService(CurrentMutationTransaction, database));
    const postconditions = yield* Effect.serviceOption(MutationPostconditions);

    if (
      Option.isSome(postconditions) &&
      !postconditions.value.register(assertApplied.pipe(translateProofFailure))
    )
      return yield* unavailable();
  });

/** Native completion reads can join a password/phone advisory snapshot. Only
 * decoded facts and the specific consumption operation cross the workflow port. */
export const completionSnapshot = Effect.fnUntraced(function* (
  mapping: N.Mapping,
  configuration: ProofSqlConfiguration,
  database: NativeSqlDatabase,
  input: ProofCompletionPlan["input"],
  mutating: boolean,
) {
  const authority = yield* N.authorityRead(mapping, input.moduleId, input.purpose, input.binding);

  const keys = mapping.scopeKeys({
    moduleId: input.moduleId,
    purpose: input.purpose,
    binding: input.binding,
  });

  const reads: SnapshotRead[] = [...authority.reads];
  const seriesIndex = reads.length;

  if (mutating) {
    const c = N.seriesColumns(mapping);

    reads.push({
      table: mapping.series.table,
      where: and(
        eq(c.moduleId, input.moduleId),
        eq(c.purpose, input.purpose),
        eq(c.scopeKey, keys.series),
      ),
      limit: 1,
    });
  }

  const c = N.continuationColumns(mapping),
    continuationIndex = reads.length;

  reads.push({
    table: mapping.continuation.table,
    where: and(eq(c.moduleId, input.moduleId), eq(c.continuationId, input.continuationId)),
    limit: 1,
  });

  return {
    reads,
    decode: (
      rows: ReadonlyArray<ReadonlyArray<Row>>,
    ): Effect.Effect<ProofCompletionRead, ProofStoreError> =>
      Effect.gen(function* () {
        const row = rows[continuationIndex]?.[0];
        const record = row === undefined ? undefined : yield* mapping.continuation.decode(row);

        return {
          authority: yield* authority.facts(rows),
          seriesPresent: !mutating || rows[seriesIndex]?.[0] !== undefined,
          continuation:
            row === undefined || record === undefined
              ? undefined
              : {
                  record,
                  consumed: row[mapping.continuation.consumed] !== false,
                  consumeCompletion: consumeCompletion(
                    mapping,
                    configuration,
                    database,
                    input,
                    row,
                    record,
                  ),
                },
        };
      }),
  };
});

export const proofCompletionStore = (
  mapping: N.Mapping,
  configuration: ProofSqlConfiguration,
  database: NativeSqlDatabase,
): ProofCompletionStore => ({
  readCompletion: (input, mutating) =>
    Effect.gen(function* () {
      const snapshot = yield* completionSnapshot(mapping, configuration, database, input, mutating);

      return yield* snapshot.decode(yield* N.readRows(database, snapshot.reads, configuration));
    }),
});

export const proofStore = (
  mapping: N.Mapping,
  configuration: ProofSqlConfiguration,
  database: NativeSqlDatabase,
  dialect: "pg" | "mysql" | "sqlite",
): ProofStore => {
  const bound = <A, E, R>(effect: Effect.Effect<A, E, R | CurrentProofSql>) =>
    effect.pipe(Effect.provideService(CurrentProofSql, database));

  const store: ProofStore = {
    readAuthority: (input, locking) =>
      Effect.gen(function* () {
        const read = yield* N.authorityRead(mapping, input.moduleId, input.purpose, input.binding);

        return yield* read.facts(
          yield* N.readRows(database, read.reads, {
            ...configuration,
            locking,
            pgOrderedLocks: locking && configuration.pgOrderedLocks === true,
          }),
        );
      }),
    lockScopes: (input) =>
      bound(
        N.lockScopes(
          mapping,
          configuration,
          input.moduleId,
          input.purpose,
          input.action,
          input.entries,
        ),
      ),
    readScopeCounts: (input, now) =>
      bound(
        N.scopeCounts(mapping, input.moduleId, input.purpose, input.action, input.entries, now),
      ),
    readSeries: (key, initialVersion) =>
      bound(
        Effect.gen(function* () {
          if (initialVersion !== undefined)
            yield* configuration.insertIfAbsent(
              database
                .insert(mapping.series.table)
                .values(mapping.series.encodeInsert({ ...key, version: initialVersion })),
              mapping.series.scopeKey,
              key.scopeKey,
            );

          return yield* decodeSeries(
            mapping,
            yield* N.readSeries(mapping, configuration, key.moduleId, key.purpose, key.scopeKey),
          );
        }),
      ),
    reserveRequest: (input) =>
      Effect.gen(function* () {
        const c = N.requestColumns(mapping),
          where = and(
            eq(c.moduleId, input.record.moduleId),
            eq(c.requestId, input.record.requestId),
          );

        let row = (yield* N.selectRows(
          database.select().from(mapping.request.table).where(where).limit(1),
          configuration.locking,
        ))[0];

        const result = (selected: Row, replay: boolean) =>
          Effect.gen(function* () {
            return {
              fingerprint: yield* text(selected[mapping.request.fingerprint]),
              proofId: yield* text(selected[mapping.request.proofId]),
              replay,
              receipt: mapping.request.decodeReceipt(selected),
            };
          });

        if (row !== undefined) {
          if ((yield* mapping.decodeInstant(row[mapping.request.retentionUntil])) > input.nowMillis)
            return yield* result(row, true);
          yield* database
            .delete(mapping.request.table)
            .where(and(where, lte(c.retentionUntil, mapping.encodeInstant(input.nowMillis))));
        }
        yield* configuration.insertIfAbsent(
          database.insert(mapping.request.table).values(
            mapping.request.encodeInsert({
              record: input.record,
              createdAtMillis: input.nowMillis,
              retentionUntilMillis: input.retentionUntilMillis,
            }),
          ),
          mapping.request.requestId,
          input.record.requestId,
        );
        row = (yield* N.selectRows(
          database.select().from(mapping.request.table).where(where).limit(1),
          configuration.locking,
        ))[0];
        if (row === undefined) return yield* unavailable();

        return yield* result(row, row[mapping.request.proofId] !== input.record.proofId);
      }),
    readGeneration: (moduleId, proofId, locking) =>
      bound(
        Effect.flatMap(N.readGeneration(mapping, moduleId, proofId, locking), (rows) =>
          decodeGeneration(mapping, rows[0]),
        ),
      ),
    readAttempt: (input) =>
      bound(
        Effect.gen(function* () {
          const series = input.includeSeries
            ? yield* store.readSeries({
                moduleId: input.attempt.moduleId,
                purpose: input.attempt.purpose,
                scopeKey: input.seriesKey,
              })
            : undefined;

          const generation = yield* store.readGeneration(
            input.attempt.moduleId,
            input.attempt.proofId,
            configuration.locking,
          );

          const command = (yield* N.commandRow(
            mapping,
            input.attempt.moduleId,
            input.attempt.continuationId,
            configuration.locking,
          ))[0];

          return {
            series,
            generation,
            command:
              command === undefined
                ? undefined
                : { decision: yield* commandDecision(command[mapping.command.decision]) },
          };
        }),
      ),
    readFailureCount: (input) =>
      bound(
        N.failureCount(
          mapping,
          input.moduleId,
          input.purpose,
          input.seriesKey,
          input.nowMillis,
          input.policy,
        ),
      ),
    publishGeneration: (input) =>
      bound(
        Effect.gen(function* () {
          yield* N.insertScopeEvents(
            mapping,
            input.record.moduleId,
            input.record.purpose,
            "issue",
            input.record.requestId,
            input.scopes,
            input.nowMillis,
            input.retentionUntilMillis,
          );

          const gc = N.generationColumns(mapping),
            sc = N.seriesColumns(mapping);

          if (input.previousProofId !== undefined)
            yield* database
              .update(mapping.generation.table)
              .set(updateValues([[mapping.generation.state, "superseded"]]))
              .where(
                and(
                  eq(gc.moduleId, input.record.moduleId),
                  eq(gc.proofId, input.previousProofId),
                  eq(gc.state, "active"),
                ),
              );
          yield* database.insert(mapping.generation.table).values(
            mapping.generation.encodeInsert({
              record: input.record,
              seriesKey: input.seriesKey,
              retentionUntilMillis: input.retentionUntilMillis,
              state: "active",
              deliveryState: "new",
              policy: input.policy,
            }),
          );
          yield* database
            .update(mapping.series.table)
            .set(
              updateValues([
                [mapping.series.activeProofId, input.record.proofId],
                [mapping.series.lastIssueAt, mapping.encodeInstant(input.nowMillis)],
                [mapping.series.version, input.nextSeriesVersion],
              ]),
            )
            .where(
              and(
                eq(sc.moduleId, input.record.moduleId),
                eq(sc.purpose, input.record.purpose),
                eq(sc.scopeKey, input.seriesKey),
              ),
            );
        }),
      ),
    recordAttempt: (write) =>
      bound(
        Effect.gen(function* () {
          const { input } = write;

          yield* N.insertCommand(
            mapping,
            input.moduleId,
            input.continuationId,
            "attempt",
            write.decision,
            write.retentionUntilMillis,
          );
          yield* N.insertScopeEvents(
            mapping,
            input.moduleId,
            input.purpose,
            "attempt",
            input.continuationId,
            write.scopes,
            write.nowMillis,
            write.retentionUntilMillis,
          );
          if (write.decision === "rejected") {
            if (write.recordFailure)
              yield* database.insert(mapping.failureEvent.table).values(
                mapping.failureEvent.encodeInsert({
                  moduleId: input.moduleId,
                  purpose: input.purpose,
                  seriesKey: write.seriesKey,
                  commandId: input.continuationId,
                  occurredAtMillis: write.nowMillis,
                  retentionUntilMillis: write.retentionUntilMillis,
                }),
              );
          } else {
            const c = N.generationColumns(mapping);

            yield* database
              .update(mapping.generation.table)
              .set(updateValues([[mapping.generation.state, "consumed"]]))
              .where(
                and(
                  eq(c.moduleId, input.moduleId),
                  eq(c.proofId, input.proofId),
                  eq(c.state, "active"),
                ),
              );
            yield* database.insert(mapping.continuation.table).values(
              mapping.continuation.encodeInsert({
                ...write.continuation,
                retentionUntilMillis: write.retentionUntilMillis,
              }),
            );
          }
        }),
      ),
    ...proofCompletionStore(mapping, configuration, database),
    readDeliverySettlement: (input) =>
      bound(
        Effect.gen(function* () {
          if (input.outcome._tag === "DefiniteFailure") {
            const initial = (yield* N.readGeneration(
              mapping,
              input.moduleId,
              input.proofId,
              false,
            ))[0];

            if (initial === undefined) return undefined;
            yield* N.ensureSeries(
              mapping,
              configuration,
              input.moduleId,
              initial[mapping.generation.purpose],
              initial[mapping.generation.seriesKey],
            );
          }

          return yield* store.readGeneration(input.moduleId, input.proofId, configuration.locking);
        }),
      ),
    writeDelivery: (input) =>
      Effect.gen(function* () {
        const c = N.generationColumns(mapping);

        if (input.transition === "ExpiredClaim")
          yield* database
            .update(mapping.generation.table)
            .set(updateValues([[mapping.generation.deliveryState, "ambiguous"]]))
            .where(and(eq(c.moduleId, input.moduleId), eq(c.proofId, input.proofId)));
        else if (input.transition === "Claim")
          yield* database
            .update(mapping.generation.table)
            .set(
              updateValues([
                [mapping.generation.sendCount, input.sendCount],
                [mapping.generation.deliveryState, "claimed"],
                [mapping.generation.claimVersion, input.claimVersion],
                [
                  mapping.generation.claimDeadline,
                  mapping.encodeInstant(input.claimDeadlineMillis),
                ],
                [mapping.generation.retryAt, mapping.encodeInstant(input.retryAtMillis)],
              ]),
            )
            .where(and(eq(c.moduleId, input.moduleId), eq(c.proofId, input.proofId)));
        else {
          const values: Array<readonly [string, unknown]> = [
            [mapping.generation.deliveryState, input.state],
            [mapping.generation.claimDeadline, null],
          ];

          if (input.retryAtMillis !== undefined)
            values.push([mapping.generation.retryAt, mapping.encodeInstant(input.retryAtMillis)]);
          if (input.state === "failed") values.push([mapping.generation.state, "cancelled"]);
          yield* database
            .update(mapping.generation.table)
            .set(updateValues(values))
            .where(
              and(
                eq(c.moduleId, input.generation.moduleId),
                eq(c.proofId, input.generation.proofId),
              ),
            );
          if (input.state === "failed") {
            const sc = N.seriesColumns(mapping);

            yield* database
              .update(mapping.series.table)
              .set(updateValues([[mapping.series.activeProofId, null]]))
              .where(
                and(
                  eq(sc.moduleId, input.generation.moduleId),
                  eq(sc.purpose, input.generation.purpose),
                  eq(sc.scopeKey, input.generation.seriesKey),
                  eq(sc.activeProofId, input.generation.proofId),
                ),
              );
          }
        }
      }),
    cancelGeneration: (key, proofId) =>
      Effect.gen(function* () {
        const gc = N.generationColumns(mapping),
          sc = N.seriesColumns(mapping);

        yield* database
          .update(mapping.generation.table)
          .set(updateValues([[mapping.generation.state, "cancelled"]]))
          .where(and(eq(gc.moduleId, key.moduleId), eq(gc.proofId, proofId)));
        yield* database
          .update(mapping.series.table)
          .set(updateValues([[mapping.series.activeProofId, null]]))
          .where(
            and(
              eq(sc.moduleId, key.moduleId),
              eq(sc.purpose, key.purpose),
              eq(sc.scopeKey, key.scopeKey),
              eq(sc.activeProofId, proofId),
            ),
          );
      }),
    readExpired: (input) => readExpiredProofs(mapping, configuration, database, dialect, input),
  };

  return store;
};

export const makeProofOwner = Effect.fnUntraced(function* (
  mapping: N.Mapping,
  configuration: ProofSqlConfiguration,
  nativeDatabase: object,
) {
  const database = nativeDatabase as NativeSqlDatabase;

  const dialect = (yield* NativeDatabase).$client.onDialectOrElse({
    pg: () => "pg" as const,
    mysql: () => "mysql" as const,
    orElse: () => "sqlite" as const,
  });

  const owner: PersistenceOwner<ProofStore> = {
    read: proofStore(mapping, configuration, database, dialect),
    transaction: (body) =>
      database.transaction((current) => {
        const store = proofStore(mapping, configuration, current, dialect);

        return body(store).pipe(
          Effect.provideService(CurrentProofSql, current),
          Effect.provideService(CurrentProofStore, store),
        );
      }),
  };

  return owner;
});

export const makeBackendProofOwner = Effect.fnUntraced(function* (
  mapping: N.Mapping,
  options: ProofWorkflowOptions & { readonly maxParameters?: number },
  database: object,
) {
  const native = yield* NativeDatabase;
  const mysql = native.$client.onDialectOrElse({ mysql: () => true, orElse: () => false });

  const configuration: ProofSqlConfiguration = {
    ...options,
    pgOrderedLocks: native.$client.onDialectOrElse({
      pg: () => options.locking,
      orElse: () => false,
    }),
    insertIfAbsent: (query, selfKey, selfValue) =>
      mysql
        ? query.onDuplicateKeyUpdate({ set: { [selfKey]: selfValue } })
        : query.onConflictDoNothing(),
  };

  return yield* makeProofOwner(mapping, configuration, database);
});
