import { makeWithDefaults } from "drizzle-orm/effect-sqlite-wasm";
import { Effect } from "effect";

import { drizzleMigrationsLayer } from "./drizzle-migrations";
import { sqlitePersistence } from "./drizzle-sqlite";

export const AuthPersistence = {
  ...sqlitePersistence(makeWithDefaults({})),
  migrationsLayer: (options: {
    readonly migrations: Record<string, string>;
    readonly migrationsTable?: string;
  }) =>
    drizzleMigrationsLayer(
      makeWithDefaults({}),
      Effect.promise(() => import("drizzle-orm/effect-sqlite-wasm/migrator")).pipe(
        Effect.map((module) => module.migrate),
      ),
    )(options),
};
