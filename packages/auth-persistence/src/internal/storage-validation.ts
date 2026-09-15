import { Effect, Schema } from "effect";
import type { SqlClient } from "effect/unstable/sql/SqlClient";

import { PersistenceConfigurationError } from "./configuration";
import type { StorageTable } from "./storage-tables";

const Column = Schema.Struct({ name: Schema.String, pk: Schema.Int });
const Index = Schema.Struct({ name: Schema.String, unique: Schema.Int, partial: Schema.Int });
const IndexColumn = Schema.Struct({ name: Schema.NullOr(Schema.String) });
const PgColumns = Schema.Array(Schema.Struct({ name: Schema.String }));
const PgKeys = Schema.Array(Schema.Struct({ columns: Schema.Array(Schema.String) }));
const quote = (value: string) => '"' + value.replaceAll('"', '""') + '"';

export const qualifiedTableName = (table: Pick<StorageTable, "name" | "schema">) =>
  (table.schema === undefined ? "" : quote(table.schema) + ".") + quote(table.name);

/** Validate physical uniqueness before the first authentication operation. A
 * partial or expression index cannot establish these unconditional guarantees. */
export const validateStorage = (
  client: SqlClient,
  dialect: "pg" | "sqlite",
  table: StorageTable,
  required: ReadonlyArray<ReadonlyArray<string>>,
) =>
  Effect.gen(function* () {
    const physicalKeys: ReadonlyArray<ReadonlyArray<string>> = yield* dialect === "sqlite"
      ? Effect.gen(function* () {
          if (table.schema !== undefined && table.schema !== "main")
            return yield* PersistenceConfigurationError.make({
              reason: "SQLite storage must belong to the main database",
            });

          const columns = yield* client`select name, pk from pragma_table_info(${table.name})`.pipe(
            Effect.flatMap(Schema.decodeUnknownEffect(Schema.Array(Column))),
          );

          for (const column of Object.values(table.columns)) {
            if (!columns.some((actual) => actual.name === column.name))
              return yield* PersistenceConfigurationError.make({
                reason: `Missing SQL column ${table.name}.${column.name}`,
              });
          }
          const keys: string[][] = [];
          const primary = columns.filter((column) => column.pk > 0).sort((a, b) => a.pk - b.pk);

          if (primary.length > 0) keys.push(primary.map((column) => column.name));

          const indexes =
            yield* client`select name, "unique", partial from pragma_index_list(${table.name})`.pipe(
              Effect.flatMap(Schema.decodeUnknownEffect(Schema.Array(Index))),
            );

          for (const index of indexes) {
            if (index.unique !== 1 || index.partial !== 0) continue;

            const columns = yield* client`select name from pragma_index_info(${index.name})`.pipe(
              Effect.flatMap(Schema.decodeUnknownEffect(Schema.Array(IndexColumn))),
            );

            if (columns.every((column) => column.name !== null))
              keys.push(columns.flatMap((column) => (column.name === null ? [] : [column.name])));
          }

          return keys;
        })
      : Effect.gen(function* () {
          const relation = qualifiedTableName(table);

          const columns =
            yield* client`select attname as name from pg_attribute where attrelid = to_regclass(${relation}) and attnum > 0 and not attisdropped`.pipe(
              Effect.flatMap(Schema.decodeUnknownEffect(PgColumns)),
            );

          for (const column of Object.values(table.columns)) {
            if (!columns.some((actual) => actual.name === column.name))
              return yield* PersistenceConfigurationError.make({
                reason: `Missing SQL column ${relation}.${column.name}`,
              });
          }

          const indexes = yield* client`
          select array_agg(a.attname order by k.ordinality) as columns
          from pg_index i
          cross join lateral unnest(i.indkey) with ordinality as k(attnum, ordinality)
          join pg_attribute a on a.attrelid = i.indrelid and a.attnum = k.attnum
          where i.indrelid = to_regclass(${relation}) and i.indisunique and i.indisvalid
            and i.indimmediate and i.indpred is null and i.indexprs is null
            and k.ordinality <= i.indnkeyatts
          group by i.indexrelid
        `.pipe(Effect.flatMap(Schema.decodeUnknownEffect(PgKeys)));

          return indexes.map((index) => index.columns);
        });

    for (const keys of required) {
      const columns = keys.map((key) => table.columns[key]?.name);

      if (
        columns.some((column) => column === undefined) ||
        !physicalKeys.some(
          (actual) =>
            actual.length === columns.length && actual.every((column) => columns.includes(column)),
        )
      )
        return yield* PersistenceConfigurationError.make({
          reason: `Missing unique key on ${table.name} (${keys.join(", ")})`,
        });
    }
  }).pipe(
    Effect.mapError((error) =>
      Schema.is(PersistenceConfigurationError)(error)
        ? error
        : PersistenceConfigurationError.make({
            reason: `Cannot validate SQL storage for ${table.name}`,
          }),
    ),
  );
