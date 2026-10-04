import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";

import { sqlClientPasswordStandaloneGuard } from "./password-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { Database } from "./sqlite-node-database";
import { makeSqlitePasswordPreparedTarget } from "./sqlite-password-prepared";
import { sqlitePasswordConfiguration } from "./sqlite-passwords";

export const { makePasswordPreparedPersistenceServices, coordinatePasswordPreparedPersistence } =
  makeSqlitePasswordPreparedTarget<Database, EffectSQLiteNodeDatabase<AnyRelations>>(
    Database,
    (service) =>
      sqlitePasswordConfiguration(
        "interactive",
        sqlClientPasswordStandaloneGuard(service),
        sqlClientProofStandaloneGuard(service),
      ),
  );
