import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./phone-target";
import { Database } from "./sqlite-node-database";

export const { makePhonePersistenceServices, coordinatePhonePersistence } = makePhoneTarget<
  Database,
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
});
