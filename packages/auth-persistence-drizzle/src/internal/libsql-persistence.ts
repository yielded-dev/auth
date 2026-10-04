import { makeWithDefaults } from "drizzle-orm/effect-libsql";
import { Effect } from "effect";

import { drizzleMigrationsLayer } from "./drizzle-migrations";
import { sqlitePersistence } from "./drizzle-sqlite";

export const AuthPersistence = {
  ...sqlitePersistence(makeWithDefaults({})),
  migrationsLayer: drizzleMigrationsLayer(
    makeWithDefaults({}),
    Effect.promise(() => import("drizzle-orm/effect-libsql/migrator")).pipe(
      Effect.map((module) => module.migrate),
    ),
  ),
};
