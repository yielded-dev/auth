import { PersistenceMappingError } from "@yielded/auth-persistence/Adapter";
import {
  and,
  getTableColumns,
  sql,
  type AnyColumn,
  type SQL,
  type SQLWrapper,
  type Table,
} from "drizzle-orm";
import type { EffectDrizzleQueryError } from "drizzle-orm/effect-core";
import { Effect } from "effect";
import type { SqlError } from "effect/sql/SqlError";

/* oxlint-disable no-explicit-any -- native table/query shapes are erased at the same boundary as the password/proof kernels. */
type Row = Record<string, any>;
type Query = Effect.Effect<ReadonlyArray<Row>, EffectDrizzleQueryError | SqlError>;

export interface SnapshotRead {
  readonly table: Table;
  readonly where: SQL | undefined;
  readonly limit?: number;
  readonly orderBy?: ReadonlyArray<SQLWrapper>;
  /** Native key text bypasses application column decoders for relationship checks. */
  readonly identities?: Readonly<Record<string, AnyColumn>>;
}

interface SnapshotQuery {
  readonly as: (name: string) => SQLWrapper & Record<string, SQLWrapper>;
  readonly getSQL: () => SQLWrapper;
}

export interface SnapshotField {
  readonly index: number;
  readonly name: string;
  readonly empty: SQLWrapper;
  readonly decode: Parameters<SQL["mapWith"]>[0];
}

/** Combine already prepared reads without acquiring a database or owning their
 * locks, bounds, final checks, or fallback policy. Native decoders stay attached
 * to the final projection; intermediate SQL only rearranges columns. */
export const combineSnapshotQueries = (
  queries: ReadonlyArray<SnapshotQuery>,
  fields: ReadonlyArray<SnapshotField>,
  lockNames?: ReadonlyArray<SQLWrapper>,
  compoundLimit = Infinity,
) => {
  const identifier = sql.identifier;
  const columns = fields.map((_, index) => identifier(`c${index}`));
  const union = (parts: ReadonlyArray<SQLWrapper>) => sql.join([...parts], sql` union all `);

  let branches = queries.map((query, index) => {
    const alias = `auth_snapshot_${index}`;
    const source = query.as(alias);

    const selection = fields.map(
      (field, position) =>
        sql`${field.index === index ? source[field.name] : field.empty} as ${columns[position]}`,
    );

    return sql`select ${index} as __auth_snapshot, ${sql.join(selection, sql`, `)}
      from ${lockNames === undefined ? source : sql`${lockNames[index]} as ${identifier(alias)}`}`;
  });

  while (branches.length > compoundLimit) {
    const groups: SQL[] = [];

    for (let offset = 0; offset < branches.length; offset += compoundLimit)
      groups.push(sql`select * from (${union(branches.slice(offset, offset + compoundLimit))})
        as ${identifier(`auth_group_${offset}`)}`);
    branches = groups;
  }

  const body = union(branches);

  const definitions = lockNames?.map(
    (name, index) => sql`${name} as materialized (${queries[index]!.getSQL()})`,
  );

  const source =
    definitions === undefined
      ? sql`(${body}) as auth_snapshot_complete`
      : sql`(with ${sql.join(definitions, sql`, `)} ${body}) as auth_snapshot_complete`;

  const selection = {
    __auth_snapshot: sql`auth_snapshot_complete.__auth_snapshot`.mapWith(Number),
    ...Object.fromEntries(
      fields.map((field, index) => [
        `c${index}`,
        sql`auth_snapshot_complete.${columns[index]}`.mapWith(field.decode),
      ]),
    ),
  };

  return {
    source,
    selection,
    regroup: (rows: ReadonlyArray<Row>): ReadonlyArray<ReadonlyArray<Row>> => {
      const groups: Row[][] = queries.map(() => []);

      for (const row of rows) {
        const index = row.__auth_snapshot;

        if (!Number.isInteger(index) || index < 0 || index >= groups.length)
          throw PersistenceMappingError.make({
            operation: "query",
            cause: "Invalid SQL snapshot index",
          });
        groups[index]!.push(
          Object.fromEntries(
            fields.flatMap((field, position) =>
              field.index === index ? [[field.name, row[`c${position}`]]] : [],
            ),
          ),
        );
      }

      return groups;
    },
  };
};

/** Direct SQL transactions have no observation journal. Batch their
 * independent readbacks without changing mapped values or joining opaque IDs. */

const lockNames = [
  sql`auth_snapshot_0`,
  sql`auth_snapshot_1`,
  sql`auth_snapshot_2`,
  sql`auth_snapshot_3`,
  sql`auth_snapshot_4`,
];

export const readSnapshot = (
  database: { readonly select: (...args: ReadonlyArray<any>) => any },
  reads: ReadonlyArray<SnapshotRead>,
  maxParameters = 96,
  pgOrderedLocks = false,
) => {
  const select = (
    { table, where, limit, orderBy, identities }: SnapshotRead,
    previous?: SQLWrapper,
  ) => {
    let query = database
      .select(
        identities === undefined
          ? undefined
          : {
              ...getTableColumns(table),
              ...Object.fromEntries(
                Object.entries(identities).map(([name, column]) => [
                  name,
                  sql`cast(${column} as text)`.mapWith(String).as(name),
                ]),
              ),
            },
      )
      .from(table)
      .where(
        and(
          where,
          previous === undefined ? undefined : sql`(select count(*) from ${previous}) >= 0`,
        ),
      );

    if (limit !== undefined) query = query.limit(limit);
    if (orderBy !== undefined) query = query.orderBy(...orderBy);

    return pgOrderedLocks ? query.for("update") : query;
  };

  const queries = reads.map((read) => select(read));

  const separate = () => ({
    singleStatement: queries.length <= 1,
    rows: Effect.forEach(queries, (query) => query as Query),
  });

  const fields = reads.flatMap((read, index) => [
    ...Object.entries(getTableColumns(read.table)).map(([name, column]) => ({
      table: read.table,
      index,
      name,
      column,
      identity: false,
    })),
    ...Object.entries(read.identities ?? {}).map(([name, column]) => ({
      table: read.table,
      index,
      name,
      column,
      identity: true,
    })),
  ]);

  const hasDecoder = (
    column: AnyColumn,
  ): column is AnyColumn & Required<Pick<AnyColumn, "mapFromDriverValue">> =>
    typeof column.mapFromDriverValue === "function";

  if (
    queries.length <= 1 ||
    (pgOrderedLocks && reads.length > lockNames.length) ||
    fields.length + 1 > (maxParameters <= 100 ? 100 : 512)
  )
    return separate();

  const projection: SnapshotField[] = [];

  for (const field of fields) {
    const decode = field.identity ? String : field.column;

    if (typeof decode !== "function" && !hasDecoder(decode)) return separate();
    projection.push({
      index: field.index,
      name: field.name,
      empty: field.identity
        ? sql`(select cast(${field.column} as text) from ${field.table} where 1 = 0)`
        : sql`(select ${field.column} from ${field.table} where 1 = 0)`,
      decode,
    });
  }

  // A later locking CTE drains its predecessor before it can lock any row.
  // This retains subject -> identifier -> credentials order independently of
  // UNION planning. Clock sampling stays in the caller after all lock waits.
  const selectedQueries = pgOrderedLocks
    ? reads.map((read, index) => select(read, lockNames[index - 1]))
    : queries;

  const combined = combineSnapshotQueries(
    selectedQueries,
    projection,
    pgOrderedLocks ? lockNames.slice(0, reads.length) : undefined,
    maxParameters <= 100 ? 5 : Infinity,
  );

  const query = database.select(combined.selection).from(combined.source);
  const rendered = query.toSQL();

  if (
    rendered.params.length > maxParameters ||
    new TextEncoder().encode(rendered.sql).length > 48_000
  )
    return separate();

  return {
    singleStatement: true,
    rows: Effect.map(query as Query, combined.regroup),
  };
};
