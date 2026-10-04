import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Effect } from "effect";

import { makeOAuthIdentityTarget } from "./oauth-drivers";
import { Database } from "./sqlite-do-database";

export const {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
} = makeOAuthIdentityTarget<
  Database,
  EffectSQLiteDoDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>,
  true
>(Database, {
  mode: "synchronous",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: () => Effect.void,
});
