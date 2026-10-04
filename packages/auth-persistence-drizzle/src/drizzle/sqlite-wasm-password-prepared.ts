import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";

import { sqlClientPasswordStandaloneGuard } from "./password-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { makeSqlitePasswordPreparedTarget } from "./sqlite-password-prepared";
import { sqlitePasswordConfiguration } from "./sqlite-passwords";
import { Database } from "./sqlite-wasm-database";

export const { makePasswordPreparedPersistenceServices, coordinatePasswordPreparedPersistence } =
  makeSqlitePasswordPreparedTarget<Database, EffectSQLiteWasmDatabase<AnyRelations>>(
    Database,
    (service) =>
      sqlitePasswordConfiguration(
        "interactive",
        sqlClientPasswordStandaloneGuard(service),
        sqlClientProofStandaloneGuard(service),
      ),
  );
