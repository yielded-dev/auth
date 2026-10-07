import { PersistenceMappingError } from "@yielded/auth-persistence/Adapter";
import {
  sql,
  getTableColumns,
  eq,
  and,
  or,
  type AnyColumn,
  type SQLWrapper,
  type SQL,
  type Table,
} from "drizzle-orm";
/* oxlint-disable no-explicit-any -- compiler handles remain private; values use native column encoders. */
import { Schema } from "effect";

import type { Row } from "./transaction-owner";

const packedRows = Schema.encodeSync(
  Schema.fromJsonString(
    Schema.Array(
      Schema.Array(Schema.Union([Schema.String, Schema.Finite, Schema.Boolean, Schema.Null])),
    ),
  ),
);

export interface BoundRows {
  readonly source: any;
  readonly fields: Readonly<Record<string, SQLWrapper>>;
  readonly exactFields: Readonly<Record<string, SQLWrapper>>;
  readonly ordinal: SQLWrapper;
  readonly rows: ReadonlyArray<Row>;
  readonly offset: number;
}

/** Encoded data is bound once. Opaque SQL encoders retain the ordinary compiler
 * path; this relation never rewrites application SQL or interpolates row values. */
export const makeBoundRows = (database: any, dialect: "pg" | "mysql" | "sqlite") => {
  const raw = sql.raw,
    identifier = sql.identifier;

  let serial = 0;

  return (
    table: Table,
    rows: ReadonlyArray<Row>,
    names?: Readonly<Record<string, string>>,
  ): ReadonlyArray<BoundRows> | undefined => {
    if (rows.length === 0) return [];
    if (dialect === "mysql") return undefined;
    const fields = Object.keys(rows[0]!).sort();

    if (dialect === "sqlite" && fields.length + 1 > 100) return undefined;
    if (
      fields.length === 0 ||
      rows.some((row) => Object.keys(row).sort().join("\0") !== fields.join("\0"))
    )
      return undefined;
    if (
      fields.some(
        (name) =>
          rows.some((row) => typeof row[name] === "string") &&
          rows.some((row) => row[name] !== null && typeof row[name] !== "string"),
      )
    )
      return undefined;

    const metadata = fields.map((name) => {
      const column = getTableColumns(table)[names?.[name] ?? name];

      return { name, column, type: column?.getSQLType?.() };
    });

    if (
      metadata.some(
        ({ column, type }) =>
          column === undefined ||
          type === undefined ||
          (Reflect.get(column, "dimensions") ?? 0) !== 0 ||
          !/^[\w ]+(?:\(\d+(?:,\s*\d+)?\))?(?: with(?:out)? time zone)?$/.test(type),
      )
    )
      return undefined;

    const encoded: Array<Array<string | number | boolean | null>> = [];

    for (const [index, row] of rows.entries()) {
      const values: Array<string | number | boolean | null> = [index];

      for (const { name, column } of metadata) {
        // The rendered parameter includes dialect normalizeParam, beyond the
        // column's mapToDriverValue. SQL-producing encoders and parameter casts
        // need their original expression, so they stay on the ordinary path.
        const binding = database
          .select({
            __auth_bound: sql`${sql.param(row[name], column!)}`.as("__auth_bound"),
          })
          .from(sql`(select 1) as auth_row_binding`)
          .toSQL();

        if (
          binding.params.length !== 1 ||
          !/^select\s+(?:\$1|\?)\s+as\s+["`]__auth_bound["`]\s+from\s+/i.test(binding.sql)
        )
          return undefined;
        const value: unknown = binding.params[0];

        if (value === null || typeof value === "string" || typeof value === "boolean")
          values.push(value);
        else if (typeof value === "number" && Number.isFinite(value)) values.push(value);
        else if (typeof value === "bigint") values.push(value.toString());
        else return undefined;
      }
      encoded.push(values);
    }

    const output: BoundRows[] = [];
    let offset = 0;
    // Leave room below SQLite DO's 2 MB binding/row bound for other parameters.
    const maximumBytes = 1_500_000;

    while (offset < rows.length) {
      let end = offset;
      let bytes = 2;

      while (end < encoded.length) {
        const size = new TextEncoder().encode(packedRows([encoded[end]!])).length;

        if (size > maximumBytes) return undefined;
        if (end > offset && bytes + size > maximumBytes) break;
        bytes += size;
        end++;
      }
      const payload = packedRows(encoded.slice(offset, end));
      const alias = `auth_rows_${serial++}`;
      const value = sql`${identifier(alias)}.${identifier("value")}`;

      const item = (index: number) =>
        dialect === "pg"
          ? sql`${value} ->> ${raw(String(index))}`
          : sql`json_extract(${value}, ${raw("'$[" + index + "]'")})`;

      const projection: Record<string, SQLWrapper> = {
        ordinal: sql`cast(${item(0)} as integer)`.mapWith(Number).as("ordinal"),
      };

      for (const [index, { name, type }] of metadata.entries()) {
        // SQLite columns have affinity, not a fixed scalar type. Keep the bound
        // value's storage class; casting here could truncate a REAL in INTEGER.
        projection[`c${index}`] = (
          dialect === "pg"
            ? sql`cast(${item(index + 1)} as ${raw(type!)})`
            : sql`${item(index + 1)}`
        ).as(`c${index}`);
        if (dialect === "pg" && rows.some((row) => typeof row[name] === "string"))
          projection[`s${index}`] = sql`${item(index + 1)}`.as(`s${index}`);
      }

      const source = database
        .select(projection)
        .from(
          dialect === "pg"
            ? sql`jsonb_array_elements(cast(${payload} as jsonb)) as ${identifier(alias)}(value)`
            : sql`json_each(${payload}) as ${identifier(alias)}`,
        )
        .as(`${alias}_values`);

      output.push({
        source,
        fields: Object.fromEntries(fields.map((name, index) => [name, source[`c${index}`]])),
        exactFields: Object.fromEntries(
          fields.map((name, index) => [
            name,
            dialect === "pg" && rows.some((row) => typeof row[name] === "string")
              ? source[`s${index}`]
              : source[`c${index}`],
          ]),
        ),
        ordinal: source.ordinal,
        rows: rows.slice(offset, end),
        offset,
      });
      offset = end;
    }

    return output;
  };
};

/** SQL NULL and byte-exact strings keep the original snapshot comparison. */
export const rowsetEquality = (
  dialect: "pg" | "mysql" | "sqlite",
  column: AnyColumn,
  value: SQLWrapper,
  strings: boolean,
): SQL => {
  if (strings) {
    if (dialect === "pg")
      return sql`convert_to(cast(${column} as text), 'UTF8') is not distinct from convert_to(cast(${value} as text), 'UTF8')`;
    if (dialect === "mysql") return sql`binary ${column} <=> binary ${value}`;

    return sql`cast(${column} as blob) is cast(${value} as blob)`;
  }
  if (dialect === "pg") return sql`${column} is not distinct from ${value}`;
  if (dialect === "mysql") return sql`${column} <=> ${value}`;

  return sql`${column} is ${value}`;
};

/** Indexed membership for bounded cleanup keys, with ordinary encoded predicates
 * when a compiler or column cannot bind a relation. Reserve the caller's base
 * parameters and split fallback predicates by their actual compiled size. */
export const makeKeyConditions = (
  database: any,
  dialect: "pg" | "mysql" | "sqlite",
  maxParameters: number,
) => {
  const bind = makeBoundRows(database, dialect);

  return (
    table: Table,
    rows: ReadonlyArray<Row>,
    names: Readonly<Record<string, string>>,
    reserved = 2,
  ): ReadonlyArray<SQL> => {
    const sets = bind(table, rows, names);
    const fields = Object.entries(names);
    const columns = getTableColumns(table);

    const output: SQL[] = [];
    let offset = 0;

    const condition = (group: ReadonlyArray<Row>) =>
      or(
        ...group.map((row) =>
          and(...fields.map(([field, name]) => eq(columns[name], row[field])))!,
        ),
      )!;

    const fits = (where: SQLWrapper) => {
      const rendered = database
        .select({ value: sql`1` })
        .from(table)
        .where(where)
        .toSQL();

      return (
        rendered.params.length + reserved <= maxParameters &&
        new TextEncoder().encode(rendered.sql).length <= (maxParameters <= 100 ? 48_000 : 512_000)
      );
    };

    if (sets !== undefined) {
      const conditions = sets.map(
        (set) =>
          sql`(${sql.join(
            fields.map(([, name]) => columns[name]),
            sql`, `,
          )}) in (select ${sql.join(
            fields.map(([field]) => set.fields[field]),
            sql`, `,
          )} from ${set.source})`,
      );

      if (conditions.every(fits)) return conditions;
    }

    while (offset < rows.length) {
      let length = Math.min(128, rows.length - offset);
      let where = condition(rows.slice(offset, offset + length));

      while (length > 1 && !fits(where)) {
        length = Math.ceil(length / 2);
        where = condition(rows.slice(offset, offset + length));
      }
      if (!fits(where))
        throw PersistenceMappingError.make({
          operation: "query",
          cause: "Cleanup key exceeds the statement limit",
        });
      output.push(where);
      offset += length;
    }

    return output;
  };
};
