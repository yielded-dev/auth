import type { ProofStore } from "@yielded/auth-persistence/Adapter";
import { and, eq, isNull, lte, notExists, sql } from "drizzle-orm";
import { Effect } from "effect";

import { updateValues } from "./model";
import type { NativeSqlDatabase, NativeSqlQuery } from "./native-database";
import { type ProofSqlConfiguration } from "./proof-database";
import {
  type Mapping,
  generationColumns,
  continuationColumns,
  requestColumns,
  abuseColumns,
  failureColumns,
  commandColumns,
  seriesColumns,
  scopeColumns,
  selectRows,
} from "./proof-native";
import { makeKeyConditions } from "./sql-rowset";

export const readExpiredProofs = Effect.fnUntraced(function* (
  mapping: Mapping,
  configuration: ProofSqlConfiguration,
  transaction: NativeSqlDatabase,
  cleanupDialect: "pg" | "mysql" | "sqlite",
  input: Parameters<ProofStore["readExpired"]>[0],
) {
  const nativeNow = mapping.encodeInstant(input.nowMillis);
  const gc = generationColumns(mapping);
  const cc = continuationColumns(mapping);
  const rc = requestColumns(mapping);
  const ac = abuseColumns(mapping);
  const fc = failureColumns(mapping);
  const mc = commandColumns(mapping);
  const sc = seriesColumns(mapping);
  const rsc = scopeColumns(mapping);
  const parameterLimit = configuration.maxParameters ?? 16_000;

  const keys = makeKeyConditions(transaction, cleanupDialect, parameterLimit);

  let remaining = input.limit;
  let hasMore = false;

  const take = <A>(query: NativeSqlQuery<ReadonlyArray<A>>) =>
    selectRows(query.limit(remaining + 1), configuration.locking).pipe(
      Effect.map((rows) => {
        if (rows.length > remaining) hasMore = true;
        const selected = rows.slice(0, remaining);

        remaining -= selected.length;

        return selected;
      }),
    );

  // Child rows and secret-bearing generations are removed before their
  // retained request/decision records. Every selected row counts toward
  // one caller-wide limit and is locked until this owner commits.
  const continuations = yield* take(
    transaction
      .select({ continuationId: cc.continuationId })
      .from(mapping.continuation.table)
      .where(and(eq(cc.moduleId, input.moduleId), lte(cc.retentionUntil, nativeNow)))
      .orderBy(cc.retentionUntil, cc.continuationId),
  );

  const generations = yield* take(
    transaction
      .select({ proofId: gc.proofId })
      .from(mapping.generation.table)
      .where(and(eq(gc.moduleId, input.moduleId), lte(gc.retentionUntil, nativeNow)))
      .orderBy(gc.retentionUntil, gc.proofId),
  );

  const requests = yield* take(
    transaction
      .select({ requestId: rc.requestId })
      .from(mapping.request.table)
      .where(and(eq(rc.moduleId, input.moduleId), lte(rc.retentionUntil, nativeNow)))
      .orderBy(rc.retentionUntil, rc.requestId),
  );

  const abuse = yield* take(
    transaction
      .select({
        action: ac.action,
        scopeKind: ac.scopeKind,
        scopeKey: ac.scopeKey,
        commandId: ac.commandId,
      })
      .from(mapping.abuseEvent.table)
      .where(and(eq(ac.moduleId, input.moduleId), lte(ac.retentionUntil, nativeNow)))
      .orderBy(ac.retentionUntil, ac.action, ac.scopeKind, ac.scopeKey, ac.commandId),
  );

  const failures = yield* take(
    transaction
      .select({ seriesKey: fc.seriesKey, commandId: fc.commandId })
      .from(mapping.failureEvent.table)
      .where(and(eq(fc.moduleId, input.moduleId), lte(fc.retentionUntil, nativeNow)))
      .orderBy(fc.retentionUntil, fc.seriesKey, fc.commandId),
  );

  const commands = yield* take(
    transaction
      .select({ commandId: mc.commandId })
      .from(mapping.command.table)
      .where(and(eq(mc.moduleId, input.moduleId), lte(mc.retentionUntil, nativeNow)))
      .orderBy(mc.retentionUntil, mc.commandId),
  );

  const series = yield* take(
    transaction
      .select({ purpose: sc.purpose, scopeKey: sc.scopeKey })
      .from(mapping.series.table)
      .where(
        and(
          eq(sc.moduleId, input.moduleId),
          isNull(sc.activeProofId),
          notExists(
            transaction
              .select({ one: sql`1` })
              .from(mapping.generation.table)
              .where(
                and(
                  eq(gc.moduleId, sc.moduleId),
                  eq(gc.purpose, sc.purpose),
                  eq(gc.seriesKey, sc.scopeKey),
                ),
              ),
          ),
          notExists(
            transaction
              .select({ one: sql`1` })
              .from(mapping.failureEvent.table)
              .where(
                and(
                  eq(fc.moduleId, sc.moduleId),
                  eq(fc.purpose, sc.purpose),
                  eq(fc.seriesKey, sc.scopeKey),
                ),
              ),
          ),
        ),
      )
      .orderBy(sc.purpose, sc.scopeKey),
  );

  const rateScopes = yield* take(
    transaction
      .select({
        purpose: rsc.purpose,
        action: rsc.action,
        scopeKind: rsc.scopeKind,
        scopeKey: rsc.scopeKey,
      })
      .from(mapping.rateScope.table)
      .where(
        and(
          eq(rsc.moduleId, input.moduleId),
          notExists(
            transaction
              .select({ one: sql`1` })
              .from(mapping.abuseEvent.table)
              .where(
                and(
                  eq(ac.moduleId, rsc.moduleId),
                  eq(ac.purpose, rsc.purpose),
                  eq(ac.action, rsc.action),
                  eq(ac.scopeKind, rsc.scopeKind),
                  eq(ac.scopeKey, rsc.scopeKey),
                ),
              ),
          ),
        ),
      )
      .orderBy(rsc.purpose, rsc.action, rsc.scopeKind, rsc.scopeKey),
  );

  // Removing the final history row can make an anchor eligible only after this
  // transaction/batch commits. One extra page lets the caller reclaim it.
  hasMore ||= generations.length > 0 || failures.length > 0 || abuse.length > 0;
  const removed = input.limit - remaining;
  const result = { removed, hasMore };

  const deleteExpired = Effect.gen(function* () {
    for (const condition of keys(mapping.continuation.table, continuations, {
      continuationId: mapping.continuation.continuationId,
    }))
      yield* transaction
        .delete(mapping.continuation.table)
        .where(and(eq(cc.moduleId, input.moduleId), condition, lte(cc.retentionUntil, nativeNow)));
    for (const condition of keys(mapping.series.table, generations, {
      proofId: mapping.series.activeProofId,
    }))
      yield* transaction
        .update(mapping.series.table)
        .set(updateValues([[mapping.series.activeProofId, null]]))
        .where(and(eq(sc.moduleId, input.moduleId), condition));
    for (const condition of keys(mapping.generation.table, generations, {
      proofId: mapping.generation.proofId,
    }))
      yield* transaction
        .delete(mapping.generation.table)
        .where(and(eq(gc.moduleId, input.moduleId), condition, lte(gc.retentionUntil, nativeNow)));
    for (const condition of keys(mapping.request.table, requests, {
      requestId: mapping.request.requestId,
    }))
      yield* transaction
        .delete(mapping.request.table)
        .where(and(eq(rc.moduleId, input.moduleId), condition, lte(rc.retentionUntil, nativeNow)));
    for (const condition of keys(mapping.abuseEvent.table, abuse, {
      action: mapping.abuseEvent.action,
      scopeKind: mapping.abuseEvent.scopeKind,
      scopeKey: mapping.abuseEvent.scopeKey,
      commandId: mapping.abuseEvent.commandId,
    }))
      yield* transaction
        .delete(mapping.abuseEvent.table)
        .where(and(eq(ac.moduleId, input.moduleId), condition, lte(ac.retentionUntil, nativeNow)));
    for (const condition of keys(mapping.failureEvent.table, failures, {
      seriesKey: mapping.failureEvent.seriesKey,
      commandId: mapping.failureEvent.commandId,
    }))
      yield* transaction
        .delete(mapping.failureEvent.table)
        .where(and(eq(fc.moduleId, input.moduleId), condition, lte(fc.retentionUntil, nativeNow)));
    for (const condition of keys(mapping.command.table, commands, {
      commandId: mapping.command.commandId,
    }))
      yield* transaction
        .delete(mapping.command.table)
        .where(and(eq(mc.moduleId, input.moduleId), condition, lte(mc.retentionUntil, nativeNow)));
    for (const condition of keys(mapping.series.table, series, {
      purpose: mapping.series.purpose,
      scopeKey: mapping.series.scopeKey,
    }))
      yield* transaction.delete(mapping.series.table).where(
        and(
          eq(sc.moduleId, input.moduleId),
          condition,
          isNull(sc.activeProofId),
          notExists(
            transaction
              .select({ one: sql`1` })
              .from(mapping.generation.table)
              .where(
                and(
                  eq(gc.moduleId, sc.moduleId),
                  eq(gc.purpose, sc.purpose),
                  eq(gc.seriesKey, sc.scopeKey),
                ),
              ),
          ),
        ),
      );
    for (const condition of keys(mapping.rateScope.table, rateScopes, {
      purpose: mapping.rateScope.purpose,
      action: mapping.rateScope.action,
      scopeKind: mapping.rateScope.scopeKind,
      scopeKey: mapping.rateScope.scopeKey,
    }))
      yield* transaction.delete(mapping.rateScope.table).where(
        and(
          eq(rsc.moduleId, input.moduleId),
          condition,
          notExists(
            transaction
              .select({ one: sql`1` })
              .from(mapping.abuseEvent.table)
              .where(
                and(
                  eq(ac.moduleId, rsc.moduleId),
                  eq(ac.purpose, rsc.purpose),
                  eq(ac.action, rsc.action),
                  eq(ac.scopeKind, rsc.scopeKind),
                  eq(ac.scopeKey, rsc.scopeKey),
                ),
              ),
          ),
        ),
      );
  });

  return { result, deleteExpired };
});
