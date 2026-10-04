import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";

import { sqlClientPasswordStandaloneGuard } from "./password-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { Database } from "./sqlite-node-database";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./sqlite-passwords";

export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = makeSqlitePasswordTarget<Database, EffectSQLiteNodeDatabase<AnyRelations>>(
  Database,
  (service) =>
    sqlitePasswordConfiguration(
      "interactive",
      sqlClientPasswordStandaloneGuard(service),
      sqlClientProofStandaloneGuard(service),
    ),
);
