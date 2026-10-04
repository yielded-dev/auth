import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./phone-target";
import { Database } from "./sqlite-bun-database";

export const { makePhonePersistenceServices, coordinatePhonePersistence } = makePhoneTarget<
  Database,
  EffectSQLiteBunDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
});
