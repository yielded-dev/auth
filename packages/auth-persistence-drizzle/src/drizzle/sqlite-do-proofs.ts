import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import { Effect } from "effect";

import { Database } from "./sqlite-do-database";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./sqlite-proofs";

/**
 * Proof mutations and coordinateProofPersistence must own their outermost
 * transactionSync call. The installed driver cannot detect an arbitrary raw
 * Drizzle outer transaction; calling either boundary from one is unsupported.
 * The owner body must remain runSync-compatible.
 */
export const { coordinateProofPersistence, makeProofPersistenceServices } = makeSqliteProofTarget<
  Database,
  EffectSQLiteDoDatabase<AnyRelations>,
  true
>(Database, sqliteProofConfiguration("synchronous", Effect.void));
