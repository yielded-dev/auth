import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";

import { sqlClientProofStandaloneGuard } from "./proof-target";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./sqlite-proofs";
import { Database } from "./sqlite-wasm-database";

export const { coordinateProofPersistence, makeProofPersistenceServices } = makeSqliteProofTarget<
  Database,
  EffectSQLiteWasmDatabase<AnyRelations>
>(Database, (service) =>
  sqliteProofConfiguration("interactive", sqlClientProofStandaloneGuard(service)),
);
