import { makeWithDefaults } from "drizzle-orm/effect-postgres";
import { Effect } from "effect";

import { drizzleMigrationsLayer } from "./drizzle-migrations";
import { postgresPersistence } from "./drizzle-postgres";

export const AuthPersistence = {
  ...postgresPersistence(makeWithDefaults({})),
  migrationsLayer: drizzleMigrationsLayer(
    makeWithDefaults({}),
    Effect.promise(() => import("drizzle-orm/effect-postgres/migrator")).pipe(
      Effect.map((module) => module.migrate),
    ),
  ),
};
