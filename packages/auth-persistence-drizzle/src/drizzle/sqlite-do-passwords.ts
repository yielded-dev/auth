import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import { Effect } from "effect";

import { Database } from "./sqlite-do-database";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./sqlite-passwords";

/**
 * Password mutations and registration must own their outer transactionSync.
 * Arbitrary raw Drizzle nesting is not detectable; owner bodies must remain
 * runSync-compatible. Detectable Effect commit scopes are rejected pre-write.
 */
export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = makeSqlitePasswordTarget<Database, EffectSQLiteDoDatabase<AnyRelations>, true>(
  Database,
  sqlitePasswordConfiguration("synchronous", Effect.void, Effect.void),
);
