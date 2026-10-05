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

interface SnapshotRead {
  readonly table: object;
  readonly where: SqlExpression | undefined;
  readonly limit?: number;
  readonly orderBy?: ReadonlyArray<SqlExpression>;
}

/** Direct SQL transactions have no observation journal. Batch their
 * independent readbacks without changing mapped values or joining opaque IDs. */
export const makeSnapshotReader = <Fragment extends SqlFragment, Column extends SqlColumn>(
  operations: QueryOperations<Fragment, Column>,
) => {
  const { and, getTableColumns, sql } = operations;
  const lockNames = [sql`auth_snapshot_0`, sql`auth_snapshot_1`, sql`auth_snapshot_2`];

  return (
    database: { readonly select: (...args: ReadonlyArray<any>) => any },
    reads: ReadonlyArray<SnapshotRead>,
    maxParameters = 96,
    pgOrderedLocks = false,
  ) => {
    const select = ({ table, where, limit, orderBy }: SnapshotRead, previous?: SqlExpression) => {
      let query = database
        .select()
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

    const fields = reads.flatMap((read, index) =>
      Object.entries(getTableColumns(read.table)).map(([name, column]) => ({
        table: read.table,
        index,
        name,
        column,
      })),
    );

    const hasDecoder = (
      column: Column,
    ): column is Column & Required<Pick<SqlColumn, "mapFromDriverValue">> =>
      typeof column.mapFromDriverValue === "function";

    if (
      queries.length <= 1 ||
      (pgOrderedLocks && reads.length > lockNames.length) ||
      fields.length + 1 > (maxParameters <= 100 ? 100 : 512) ||
      fields.some(({ column }) => !hasDecoder(column))
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
            : sql`(select ${field.column} from ${field.table} where 1 = 0)`;

        if (hasDecoder(field.column))
          selection[`c${fieldIndex}`] = value.mapWith(field.column).as(`c${fieldIndex}`);
      }

      return database.select(selection).from(pgOrderedLocks ? lockNames[index] : source);
    });

    let query = branches.slice(1).reduce((joined, branch) => joined.unionAll(branch), branches[0]);

    if (pgOrderedLocks) {
      const source = query.as("auth_snapshot_complete");

      const selection: Row = {
        __auth_snapshot: sql`${source.__auth_snapshot}`.mapWith(Number),
      };

      for (const [fieldIndex, field] of fields.entries())
        if (hasDecoder(field.column))
          selection[`c${fieldIndex}`] = sql`${source[`c${fieldIndex}`]}`.mapWith(field.column);

      const definitions = selectedQueries.map(
        (selected, index) => sql`${lockNames[index]} as materialized (${selected.getSQL()})`,
      );

      query = database.select(selection).from(sql`(with ${sql.join(definitions, sql`, `)}
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
