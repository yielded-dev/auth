import {
  makeOAuthProxyPersistence,
  validateStorage,
  type OAuthProxySqlTable,
} from "@yielded/auth-persistence/Adapter";
import { ConfigurationError, Persistence } from "@yielded/auth/OAuthProxy";
import { getTableColumns, is, type Table } from "drizzle-orm";
import { getTableConfig as pgConfig, PgTable } from "drizzle-orm/pg-core";
import { getTableConfig as sqliteConfig, SQLiteTable } from "drizzle-orm/sqlite-core";
import { Effect, Layer } from "effect";
import { SqlClient } from "effect/sql";

/** Override logical column keys when using an application-owned table. */
export type OAuthProxyColumns<T extends Table> = Partial<{
  readonly [K in keyof OAuthProxySqlTable["columns"]]: Extract<keyof T["_"]["columns"], string>;
}>;

/** The shared SQL kernel writes plain text and integer milliseconds directly;
 * Drizzle value codecs and write hooks do not run for these storage columns. */
export const oauthProxyLayer = <T extends Table>(
  dialect: "sqlite" | "pg",
  table: T,
  columns: OAuthProxyColumns<T> = {},
) =>
  Layer.effect(
    Persistence,
    Effect.gen(function* () {
      const client = (yield* SqlClient.SqlClient).withoutTransforms();

      if (
        client.onDialectOrElse({
          sqlite: () => "sqlite",
          pg: () => "pg",
          orElse: () => "other",
        }) !== dialect
      )
        return yield* ConfigurationError.make({});

      const mapping = yield* Effect.try({
        try: (): OAuthProxySqlTable => {
          const config =
            dialect === "pg" && is(table, PgTable)
              ? pgConfig(table)
              : dialect === "sqlite" && is(table, SQLiteTable)
                ? sqliteConfig(table)
                : undefined;

          if (config === undefined) throw ConfigurationError.make({});
          const declared = getTableColumns(table);

          const column = (key: keyof OAuthProxySqlTable["columns"]) => {
            const field = declared[columns[key] ?? key];
            const integer = key === "expiresAtMillis" || key === "handoffExpiresAtMillis";

            if (
              field === undefined ||
              !(integer
                ? ["integer", "bigint"].includes(field.getSQLType())
                : field.getSQLType() === "text") ||
              field.notNull !== (key !== "handoffExpiresAtMillis")
            )
              throw ConfigurationError.make({});

            return field.name;
          };

          return {
            name: config.name,
            ...("schema" in config && config.schema !== undefined ? { schema: config.schema } : {}),
            columns: {
              namespace: column("namespace"),
              flowId: column("flowId"),
              version: column("version"),
              stage: column("stage"),
              context: column("context"),
              expiresAtMillis: column("expiresAtMillis"),
              handoffExpiresAtMillis: column("handoffExpiresAtMillis"),
              payload: column("payload"),
            },
          };
        },
        catch: () => ConfigurationError.make({}),
      });

      yield* validateStorage(
        dialect,
        {
          ...mapping,
          columns: Object.fromEntries(
            Object.entries(mapping.columns).map(([key, name]) => [key, { name }]),
          ),
        },
        [["namespace", "flowId"]],
      ).pipe(
        Effect.provideService(SqlClient.SqlClient, client),
        Effect.mapError(() => ConfigurationError.make({})),
      );

      return yield* makeOAuthProxyPersistence(mapping);
    }),
  );
