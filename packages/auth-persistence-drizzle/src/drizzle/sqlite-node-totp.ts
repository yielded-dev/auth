import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { Database } from "./sqlite-node-database";
import { makeTotpTarget, sqlClientTotpStandaloneGuard } from "./totp-target";

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = makeTotpTarget<
  Database,
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientTotpStandaloneGuard,
});
