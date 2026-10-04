import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";

import { sqlClientPasswordStandaloneGuard } from "./password-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { Database } from "./sqlite-bun-database";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./sqlite-passwords";

export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = makeSqlitePasswordTarget<Database, EffectSQLiteBunDatabase<AnyRelations>>(Database, (service) =>
  sqlitePasswordConfiguration(
    "interactive",
    sqlClientPasswordStandaloneGuard(service),
    sqlClientProofStandaloneGuard(service),
  ),
);
