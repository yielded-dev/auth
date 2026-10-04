import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import { Effect } from "effect";

import { Database } from "./sqlite-do-database";
import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./sqlite-emails";

/**
 * Email mutations must own their outer transactionSync. Arbitrary raw Drizzle
 * nesting is not detectable; owner bodies and mapping allocators stay runSync-compatible.
 */
export const {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} = makeSqliteEmailTarget<Database, EffectSQLiteDoDatabase<AnyRelations>, true>(
  Database,
  sqliteEmailConfiguration("synchronous", Effect.void, Effect.void),
);
