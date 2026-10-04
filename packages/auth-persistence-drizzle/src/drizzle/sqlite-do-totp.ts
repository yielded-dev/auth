import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Effect } from "effect";

import { Database } from "./sqlite-do-database";
import { makeTotpTarget } from "./totp-target";

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = makeTotpTarget<
  Database,
  EffectSQLiteDoDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>,
  unknown,
  true
>(Database, {
  mode: "synchronous",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: () => Effect.void,
});
