import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { Database } from "./sqlite-wasm-database";
import { makeTotpTarget, sqlClientTotpStandaloneGuard } from "./totp-target";

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = makeTotpTarget<
  Database,
  EffectSQLiteWasmDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientTotpStandaloneGuard,
});
