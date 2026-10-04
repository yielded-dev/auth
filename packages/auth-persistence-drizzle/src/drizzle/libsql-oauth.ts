import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { Database } from "./libsql-database";
import { makeOAuthIdentityTarget } from "./oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./oauth-execution";

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
  EffectLibsqlDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientOAuthStandaloneGuard,
});
