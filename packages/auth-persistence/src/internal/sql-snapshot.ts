import { Effect } from "effect";
import type { SqlError } from "effect/sql/SqlError";

import type {
  QueryFailure,
  QueryOperations,
  SqlColumn,
  SqlExpression,
  SqlFragment,
} from "./query-operations";

/* oxlint-disable no-explicit-any -- native table/query shapes are erased at the same boundary as the password/proof kernels. */
type Row = Record<string, any>;
type Query = Effect.Effect<ReadonlyArray<Row>, QueryFailure | SqlError>;

export interface SnapshotRead {
  readonly table: object;
  readonly where: SqlExpression | undefined;
  readonly limit?: number;
  readonly orderBy?: ReadonlyArray<SqlExpression>;
  /** Native key text bypasses application column decoders for relationship checks. */
  readonly identities?: Readonly<Record<string, SqlColumn>>;
}

/** Direct SQL transactions have no observation journal. Batch their
 * independent readbacks without changing mapped values or joining opaque IDs. */
export const makeSnapshotReader = <Fragment extends SqlFragment, Column extends SqlColumn>(
  operations: QueryOperations<Fragment, Column>,
) => {
  const { and, getTableColumns, sql } = operations;

  const lockNames = [
    sql`auth_snapshot_0`,
    sql`auth_snapshot_1`,
    sql`auth_snapshot_2`,
    sql`auth_snapshot_3`,
    sql`auth_snapshot_4`,
  ];

  return (
    database: { readonly select: (...args: ReadonlyArray<any>) => any },
    reads: ReadonlyArray<SnapshotRead>,
    maxParameters = 96,
    pgOrderedLocks = false,
  ) => {
    const select = (
      { table, where, limit, orderBy, identities }: SnapshotRead,
      previous?: SqlExpression,
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
      column: SqlColumn,
    ): column is SqlColumn & Required<Pick<SqlColumn, "mapFromDriverValue">> =>
      typeof column.mapFromDriverValue === "function";

    if (
      queries.length <= 1 ||
      (pgOrderedLocks && reads.length > lockNames.length) ||
      fields.length + 1 > (maxParameters <= 100 ? 100 : 512) ||
      fields.some(({ column, identity }) => !identity && !hasDecoder(column))
    )
      return separate();

    // A later locking CTE drains its predecessor before it can lock any row.
    // This retains subject -> identifier -> credentials order independently of
    // UNION planning. Clock sampling stays in the caller after all lock waits.
    const selectedQueries = pgOrderedLocks
      ? reads.map((read, index) => select(read, lockNames[index - 1]))
      : queries;

    const branches = selectedQueries.map((query, index) => {
      const source = query.as(`auth_snapshot_${index}`);

      const selection: Row = {
        __auth_snapshot: sql`${index}`.mapWith(Number).as("__auth_snapshot"),
      };

      for (const [fieldIndex, field] of fields.entries()) {
        const value =
          field.index === index
            ? sql`${source[field.name]}`
            : field.identity
              ? sql`(select cast(${field.column} as text) from ${field.table} where 1 = 0)`
              : sql`(select ${field.column} from ${field.table} where 1 = 0)`;

        if (field.identity)
          selection[`c${fieldIndex}`] = value.mapWith(String).as(`c${fieldIndex}`);
        else if (hasDecoder(field.column))
          selection[`c${fieldIndex}`] = value.mapWith(field.column).as(`c${fieldIndex}`);
      }

      return database.select(selection).from(pgOrderedLocks ? lockNames[index] : source);
    });

    const projection = (source: any) => {
      const selection: Row = {
        __auth_snapshot: sql`${source.__auth_snapshot}`.mapWith(Number),
      };

      for (const [fieldIndex, field] of fields.entries())
        if (field.identity)
          selection[`c${fieldIndex}`] = sql`${source[`c${fieldIndex}`]}`.mapWith(String);
        else if (hasDecoder(field.column))
          selection[`c${fieldIndex}`] = sql`${source[`c${fieldIndex}`]}`.mapWith(field.column);

      return selection;
    };

    const union = (parts: ReadonlyArray<any>) =>
      parts.slice(1).reduce((joined, part) => joined.unionAll(part), parts[0]);

    // SQLite on Durable Objects permits five terms in each compound SELECT.
    // Nest bounded groups so a wider snapshot still uses one database call.
    let grouped = branches;
    let level = 0;

    while (maxParameters <= 100 && grouped.length > 5) {
      const next: any[] = [];

      for (let offset = 0; offset < grouped.length; offset += 5) {
        const source = union(grouped.slice(offset, offset + 5)).as(`auth_group_${level}_${offset}`);

        next.push(database.select(projection(source)).from(source));
      }
      grouped = next;
      level++;
    }

    let query = union(grouped);

    if (pgOrderedLocks) {
      const source = query.as("auth_snapshot_complete");

      const definitions = selectedQueries.map(
        (selected, index) => sql`${lockNames[index]} as materialized (${selected.getSQL()})`,
      );

      query = database.select(projection(source)).from(sql`(with ${sql.join(definitions, sql`, `)}
        ${query.getSQL()}) as auth_snapshot_complete`);
    }
    const rendered = query.toSQL();

    if (
      rendered.params.length > maxParameters ||
      new TextEncoder().encode(rendered.sql).length > 48_000
    )
      return separate();

    return {
      singleStatement: true,
      rows: Effect.map(query as Query, (rows) =>
        reads.map((_, index) =>
          rows
            .filter((row) => row.__auth_snapshot === index)
            .map((row) =>
              Object.fromEntries(
                fields.flatMap((field, fieldIndex) =>
                  field.index === index ? [[field.name, row[`c${fieldIndex}`]]] : [],
                ),
              ),
            ),
        ),
      ),
    };
  };
};
