import { makeWithDefaults } from "drizzle-orm/effect-sqlite-node";
import { Effect } from "effect";

import { drizzleMigrationsLayer } from "./drizzle-migrations";
import { sqlitePersistence } from "./drizzle-sqlite";

export const AuthPersistence = {
  ...sqlitePersistence(makeWithDefaults({})),
  migrationsLayer: drizzleMigrationsLayer(
    makeWithDefaults({}),
    Effect.promise(() => import("drizzle-orm/effect-sqlite-node/migrator")).pipe(
      Effect.map((module) => module.migrate),
    ),
  ),
};
