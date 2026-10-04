import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { makeOAuthIdentityTarget } from "./oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./oauth-execution";
import { Database } from "./sqlite-node-database";

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
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientOAuthStandaloneGuard,
});
