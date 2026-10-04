import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";

import { sqlClientProofStandaloneGuard } from "./proof-target";
import { Database } from "./sqlite-bun-database";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./sqlite-proofs";

export const { coordinateProofPersistence, makeProofPersistenceServices } = makeSqliteProofTarget<
  Database,
  EffectSQLiteBunDatabase<AnyRelations>
>(Database, (service) =>
  sqliteProofConfiguration("interactive", sqlClientProofStandaloneGuard(service)),
);
