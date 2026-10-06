import {
  PersistenceMappingError,
  makeNativeSqlTables,
  nativeSqlAlias,
  type NativeSqlTables,
  type SqlTable,
} from "@yielded/auth-persistence/Adapter";
import {
  getTableColumns,
  is,
  Param,
  Placeholder,
  type SQL,
  Table,
  sql,
  type BuildQueryConfig,
  type SQLWrapper,
} from "drizzle-orm";
import { Predicate } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";
import * as Statement from "effect/sql/Statement";

type CapturedDialect = Pick<BuildQueryConfig, "escapeName" | "escapeString" | "codecs">;

/** Foreign compiler boundary only: builders are used to materialize SQL, never
 * executed. The select builder exposes the original dialect even through the
 * Durable Object database projection, which retains bound query methods. */
interface CapturedDatabase {
  readonly select: () => { readonly dialect: CapturedDialect };
  readonly insert: (table: Table) => {
    readonly values: (values: Record<string, unknown>) => SQLWrapper;
  };
  readonly update: (table: Table) => {
    readonly set: (values: Record<string, unknown>) => SQLWrapper;
  };
}

const invalid = (cause: string): never => {
  throw PersistenceMappingError.make({ operation: "mapping", cause });
};

const capture = (database: object): CapturedDatabase => {
  if (
    !Predicate.hasProperty(database, "select") ||
    typeof database.select !== "function" ||
    !Predicate.hasProperty(database, "insert") ||
    typeof database.insert !== "function" ||
    !Predicate.hasProperty(database, "update") ||
    typeof database.update !== "function"
  )
    return invalid("Expected a captured Drizzle database");

  // Drizzle's private dialect and generic query builders are erased only here.
  return database as CapturedDatabase;
};

const compileWith =
  (dialect: CapturedDialect) =>
  (expression: SQL): Statement.Fragment => {
    const slots: string[] = [];

    const query = expression.toQuery({
      escapeName: (name) => {
        if (name.includes("\0")) return invalid("NUL in SQL identifier");

        return dialect.escapeName(name);
      },
      escapeString: (value) => {
        if (value.includes("\0")) return invalid("NUL in SQL literal");

        return dialect.escapeString(value);
      },
      escapeParam: (index) => {
        if (index !== slots.length) return invalid("Invalid Drizzle parameter order");
        const slot = `yielded_parameter_${index}`;

        slots.push(slot);

        return `\0${slot}\0`;
      },
      ...(dialect.codecs === undefined ? {} : { codecs: dialect.codecs }),
    });

    // Only compiler-emitted slots are translated. Native Statement parameters
    // receive their final positions when composed; SQL literals containing $1 or
    // ? are never inspected or rewritten. NUL is reserved for this compilation.
    const parts = query.sql.split("\0");

    if (parts.length !== slots.length * 2 + 1 || query.params.length !== slots.length)
      return invalid("NUL or parameter marker collision in Drizzle SQL");

    const segments: Statement.Segment[] = [];
    const consumed = new Set<number>();

    for (let offset = 0; offset < parts.length; offset += 2) {
      segments.push(Statement.literal(parts[offset]));
      if (offset + 1 === parts.length) break;
      const index = slots.indexOf(parts[offset + 1]);

      if (index < 0 || consumed.has(index))
        return invalid("NUL or parameter marker collision in Drizzle SQL");
      consumed.add(index);
      const value: unknown = query.params[index];

      if (is(value, Placeholder) || is(value, Param)) return invalid("Unbound Drizzle placeholder");
      if (Statement.isFragment(value)) segments.push(...value.segments);
      else segments.push(Statement.parameter(value));
    }

    return Statement.fragment(segments);
  };

/** Preserve native Statement expressions in writes without applying a column
 * codec to them. Ordinary values still pass through Drizzle's own builders. */
const writeValues = (values: Readonly<Record<string, unknown>>) =>
  Object.fromEntries(
    Object.entries(values).map(([key, value]) => [
      key,
      Statement.isFragment(value) ? sql`${sql.param(value)}` : value,
    ]),
  );

/** Capture the root database's compiler, not a later transaction object's
 * client. Call insert/update inside the operation to materialize hooks once. */
export const makeDrizzleSqlTables = (
  client: SqlClient,
  capturedDatabase: object,
): NativeSqlTables => {
  const database = capture(capturedDatabase);
  const dialect = database.select().dialect;
  const compile = compileWith(dialect);

  return makeNativeSqlTables(client, (_client, physical): SqlTable => {
    if (!is(physical, Table)) return invalid("Expected a Drizzle table");
    const columns = getTableColumns(physical);
    const entries = Object.entries(columns);

    const getColumn = (key: string) => {
      const column = Object.hasOwn(columns, key) ? columns[key] : undefined;

      if (column === undefined) return invalid("Missing Drizzle column");

      return column;
    };

    const bind = (alias?: string): SqlTable => {
      const reference = (key: string) => {
        const column = getColumn(key);

        return alias === undefined
          ? sql`${column}`
          : sql`${sql.identifier(alias)}.${sql.identifier(column.name)}`;
      };

      return {
        name: compile(
          alias === undefined ? sql`${physical}` : sql`${physical} AS ${sql.identifier(alias)}`,
        ),
        as: bind,
        column: (key) => compile(reference(key)),
        fields: (prefix) =>
          compile(
            sql.join(
              entries.map(([key, column], index) => {
                const selection =
                  dialect.codecs === undefined
                    ? reference(key)
                    : dialect.codecs.apply(column, "cast", reference(key));

                return sql`${selection} as ${sql.identifier(nativeSqlAlias(prefix, index))}`;
              }),
              sql`, `,
            ),
          ),
        decode: (row, prefix) =>
          Object.fromEntries(
            entries.map(([key, column], index) => {
              const alias = nativeSqlAlias(prefix, index);

              if (!Object.hasOwn(row, alias)) return invalid("Missing SQL projection field");
              const value = row[alias];

              return [
                key,
                value === null
                  ? null
                  : column.mapFromDriverValue(
                      dialect.codecs === undefined
                        ? value
                        : dialect.codecs.apply(column, "normalize", value),
                    ),
              ];
            }),
          ),
        value: (key, value) => {
          const column = getColumn(key);

          return Statement.isFragment(value) ? value : compile(sql`${sql.param(value, column)}`);
        },
        insert: (values) => compile(database.insert(physical).values(writeValues(values)).getSQL()),
        update: (values) => compile(database.update(physical).set(writeValues(values)).getSQL()),
      };
    };

    return bind();
  });
};
