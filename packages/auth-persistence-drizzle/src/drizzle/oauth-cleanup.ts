import { getTableColumns, or, sql, type SQL, type Table } from "drizzle-orm";
import type { EffectDrizzleQueryError } from "drizzle-orm/effect-core";
import { Effect } from "effect";

import { CurrentOAuthTransaction, equal, matchesNativeRow, type Row } from "./oauth-owner";
import { invariant, unavailable } from "./oauth-state";

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

/** Native cleanup retains full snapshots under bounded identities, never a due/page
 * predicate whose membership changes during cleanup. D1 keeps its staged path. */
export const observeCleanupRows = Effect.fnUntraced(function* (
  table: Table,
  rows: ReadonlyArray<Row>,
  key: (row: Row) => Row,
) {
  const owner = yield* CurrentOAuthTransaction;

  invariant(!owner.batch);
  if (owner.rowsets(table, rows.map(key)) !== undefined) {
    yield* owner.observeKeys(table, rows.map(key), rows);

    return;
  }
  for (const row of rows) yield* owner.observe(table, equal(table, key(row)), [row]);
});

/** Evaluate each reference predicate once over encoded inputs. Accepted rows keep
 * the same correlated predicate after every write and AFTER trigger. */
export const checkCleanupRows = Effect.fnUntraced(function* (
  table: Table,
  rows: ReadonlyArray<Row>,
  condition: (fields: Row) => SQL,
) {
  const owner = yield* CurrentOAuthTransaction;

  invariant(!owner.batch);
  const accepted: boolean[] = [];
  const sets = owner.rowsets(table, rows);

  const fields = (values: Readonly<Record<string, unknown>>) =>
    Object.fromEntries(Object.entries(values).map(([name, value]) => [name, sql`${value}`]));

  const queries = sets?.map((set) => ({
    set,
    query: owner.database
      .select({
        ordinal: sql`${set.ordinal}`.mapWith(Number),
        accepted: sql`case when ${condition(fields(set.fields))} then 1 else 0 end`.mapWith(Number),
      })
      .from(set.source)
      .orderBy(set.ordinal),
  }));

  if (
    queries !== undefined &&
    queries.every(({ query }) => cleanupQueryFits(query, owner.maxParameters))
  ) {
    for (const { set, query } of queries) {
      const result = yield* (
        query as Effect.Effect<ReadonlyArray<Row>, EffectDrizzleQueryError>
      ).pipe(Effect.mapError(unavailable));

      invariant(result.length === set.rows.length);
      for (const [index, row] of result.entries()) {
        invariant(row.ordinal === set.offset + index && (row.accepted === 0 || row.accepted === 1));
        accepted.push(row.accepted === 1);
      }
    }

    const retained = owner.rowsets(
      table,
      rows.filter((_, index) => accepted[index]),
    );

    invariant(retained !== undefined);
    for (const set of retained)
      owner.postconditions.push(
        sql`not exists(select 1 from ${set.source} where case when ${condition(fields(set.fields))} then 0 else 1 end = 1)`,
      );

    return accepted;
  }

  // The constructor accepts native values as well as SQL fields, just like
  // externalReference. Fallback values use each reference column's own encoder.
  const conditions = rows.map(condition);

  for (let offset = 0; offset < conditions.length;) {
    let chunk = conditions.slice(offset, offset + 64);

    const select = (selected: ReadonlyArray<SQL>) =>
      owner.database
        .select(
          Object.fromEntries(
            selected.map((value, index) => [
              String(index),
              sql`case when ${value} then 1 else 0 end`.mapWith(Number),
            ]),
          ),
        )
        .from(sql`(select 1) as oauth_collection_checks`);

    let query = select(chunk);

    while (chunk.length > 1 && !cleanupQueryFits(query, owner.maxParameters)) {
      chunk = chunk.slice(0, Math.ceil(chunk.length / 2));
      query = select(chunk);
    }
    invariant(cleanupQueryFits(query, owner.maxParameters));

    const result = yield* (
      query as Effect.Effect<ReadonlyArray<Row>, EffectDrizzleQueryError>
    ).pipe(Effect.mapError(unavailable));

    invariant(result.length === 1);
    for (const [index, value] of chunk.entries()) {
      const holds = result[0]![String(index)];

      invariant(holds === 0 || holds === 1);
      accepted.push(holds === 1);
      if (holds === 1) owner.postconditions.push(value);
    }
    offset += chunk.length;
  }

  return accepted;
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

  if (
    yield* owner.changeRows(
      table,
      rows.map((row) => {
        const expected = update?.expected(row);

        return {
          key: key(row),
          before: row,
          after:
            update === undefined
              ? null
              : Object.fromEntries(
                  Object.keys(update.values).map((name) => [name, expected![name]]),
                ),
        };
      }),
    )
  )
    return;

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
