import { getTableColumns, or, sql, type Table } from "drizzle-orm";
import { Effect } from "effect";

import { CurrentOAuthTransaction, equal, matchesNativeRow, type Row } from "./oauth-owner";
import { invariant } from "./oauth-state";

/** Render only generated Drizzle queries; application SQL is never rewritten. */
export const cleanupQueryFits = (
  query: {
    readonly toSQL: () => { readonly sql: string; readonly params: ReadonlyArray<unknown> };
  },
  maxParameters: number,
) => {
  const rendered = query.toSQL();

  return (
    rendered.params.length <= maxParameters &&
    (maxParameters > 100 || new TextEncoder().encode(rendered.sql).length <= 48_000)
  );
};

/** Native cleanup retains full snapshots under point identities, never a due/page
 * predicate whose membership changes during cleanup. D1 keeps its staged path. */
export const observeCleanupRows = Effect.fnUntraced(function* (
  table: Table,
  rows: ReadonlyArray<Row>,
  key: (row: Row) => Row,
) {
  const owner = yield* CurrentOAuthTransaction;

  invariant(!owner.batch);
  for (const row of rows) yield* owner.observe(table, equal(table, key(row)), [row]);
});

/** Bound exact-row writes by the native SQLite bind budget. Final observations
 * verify every survivor or deleted identity after all writes and AFTER triggers. */
export const writeCleanupRows = Effect.fnUntraced(function* (
  table: Table,
  rows: ReadonlyArray<Row>,
  key: (row: Row) => Row,
  update?: {
    readonly values: Row;
    readonly expected: (row: Row) => Row;
  },
) {
  const owner = yield* CurrentOAuthTransaction;

  invariant(!owner.batch);
  // SQL collation may discover an alias. Preserve the native key comparison
  // used by owner.update/remove before adopting a successful bulk mutation.
  invariant(rows.every((row) => matchesNativeRow(table, row, key(row))));

  const size = Math.max(
    1,
    Math.min(
      64,
      Math.floor(
        Math.min(800, owner.maxParameters - Object.keys(update?.values ?? {}).length) /
          Object.keys(getTableColumns(table)).length,
      ),
    ),
  );

  for (let offset = 0; offset < rows.length;) {
    let group = rows.slice(offset, offset + size);

    const build = (selected: ReadonlyArray<Row>) => {
      const where = or(...selected.map((row) => sql`${owner.exact(table, row)}`));

      return update === undefined
        ? owner.database.delete(table).where(where)
        : owner.database.update(table).set(update.values).where(where);
    };

    let query = build(group);

    while (group.length > 1 && !cleanupQueryFits(query, owner.maxParameters)) {
      group = group.slice(0, Math.ceil(group.length / 2));
      query = build(group);
    }
    invariant(cleanupQueryFits(query, owner.maxParameters));
    yield* owner.write(query);
    offset += group.length;
    for (const observation of owner.observations) {
      if (observation.table !== table) continue;
      observation.rows = observation.rows.flatMap((row) => {
        const selected = group.find((candidate) => matchesNativeRow(table, row, key(candidate)));

        return selected === undefined ? [row] : update === undefined ? [] : [update.expected(row)];
      });
    }
  }
});
