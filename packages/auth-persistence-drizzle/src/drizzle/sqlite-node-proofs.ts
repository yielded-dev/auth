import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";

import { sqlClientProofStandaloneGuard } from "./proof-target";
import { Database } from "./sqlite-node-database";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./sqlite-proofs";

export const { coordinateProofPersistence, makeProofPersistenceServices } = makeSqliteProofTarget<
  Database,
  EffectSQLiteNodeDatabase<AnyRelations>
>(Database, (service) =>
  sqliteProofConfiguration("interactive", sqlClientProofStandaloneGuard(service)),
);
