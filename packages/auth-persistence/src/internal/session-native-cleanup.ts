import type { LifecycleHooks } from "@yielded/auth/Hooks";
import type { SessionCleanup } from "@yielded/auth/Sessions";
import { Effect } from "effect";
import { SqlClient } from "effect/sql/SqlClient";

import type { SessionCleanupMapping } from "./models/session-model";
import type { NativeSqlTables } from "./native-sql-table";
import { sessionUnavailable } from "./session-native-state";
import { exactSqlText } from "./sql-change";
import { cleanupSqlRows, type SqlCleanupTable } from "./sql-cleanup";
import { makeSqlCommitExecutor, SqlBatchCommit } from "./sql-commit";
import type { AnyTableModel } from "./table-model";

export const makeNativeSessionCleanupServices = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: SessionCleanupMapping<AnyTableModel, AnyTableModel, unknown, unknown>,
  batch?: SqlBatchCommit["Service"],
): Effect.fn.Return<
  { readonly sessionCleanup: SessionCleanup },
  never,
  SqlClient | LifecycleHooks
> {
  const sql = (yield* SqlClient).withoutTransforms();
  const executor = yield* makeSqlCommitExecutor(sessionUnavailable);
  const now = tables.expression(mapping.clock.engineNowMillis);
  const candidates: SqlCleanupTable[] = [];

  if (mapping.pending !== undefined) {
    const p = mapping.pending,
      table = tables(p.table);

    candidates.push({
      table,
      keys: [p.digest],
      due: sql`${exactSqlText(sql, table.column(p.moduleId), table.value(p.moduleId, mapping.moduleId))} and ${tables.expression(mapping.clock.toMillis(table.column(p.expiresAt)))} <= ${now}`,
      order: [table.column(p.expiresAt), table.column(p.digest)],
    });
  }
  if (mapping.tombstone !== undefined) {
    const t = mapping.tombstone,
      table = tables(t.table);

    candidates.push({
      table,
      keys: [t.moduleId, t.subjectId, t.sessionId],
      due: sql`${exactSqlText(sql, table.column(t.moduleId), table.value(t.moduleId, mapping.moduleId))} and ${tables.expression(mapping.clock.toMillis(table.column(t.absoluteExpiresAt)))} <= ${now}`,
      order: [table.column(t.absoluteExpiresAt), table.column(t.sessionId)],
    });
  }

  return {
    sessionCleanup: {
      cleanup: ({ limit }) => {
        if (candidates.length === 0)
          return executor.read(Effect.succeed({ removed: 0, hasMore: false }));
        const work = cleanupSqlRows(candidates, limit, batch !== undefined);

        return batch === undefined
          ? executor.run(work, candidates.length > 1 ? "transaction" : "statement")
          : executor.batch(work).pipe(Effect.provideService(SqlBatchCommit, batch));
      },
    },
  };
});
