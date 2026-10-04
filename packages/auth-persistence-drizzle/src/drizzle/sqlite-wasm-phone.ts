import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./phone-target";
import { Database } from "./sqlite-wasm-database";

export const { makePhonePersistenceServices, coordinatePhonePersistence } = makePhoneTarget<
  Database,
  EffectSQLiteWasmDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
});
