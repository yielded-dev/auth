import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { makeOAuthIdentityTarget } from "./oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./oauth-execution";
import { Database } from "./sqlite-bun-database";

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
  EffectSQLiteBunDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientOAuthStandaloneGuard,
});
