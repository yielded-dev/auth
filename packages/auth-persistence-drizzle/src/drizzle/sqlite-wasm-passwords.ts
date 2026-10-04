import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";

import { sqlClientPasswordStandaloneGuard } from "./password-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./sqlite-passwords";
import { Database } from "./sqlite-wasm-database";

export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = makeSqlitePasswordTarget<Database, EffectSQLiteWasmDatabase<AnyRelations>>(
  Database,
  (service) =>
    sqlitePasswordConfiguration(
      "interactive",
      sqlClientPasswordStandaloneGuard(service),
      sqlClientProofStandaloneGuard(service),
    ),
);
