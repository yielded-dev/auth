import type { AnyRelations } from "drizzle-orm";
import type { EffectMysql2Database } from "drizzle-orm/effect-mysql2";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core";

import { Database } from "./mysql-database";
import { makeOAuthIdentityTarget } from "./oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./oauth-execution";
import { mysqlOAuthTransaction } from "./oauth-mysql";

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
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>(Database, {
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  transaction: mysqlOAuthTransaction,
  standaloneGuard: sqlClientOAuthStandaloneGuard,
});
