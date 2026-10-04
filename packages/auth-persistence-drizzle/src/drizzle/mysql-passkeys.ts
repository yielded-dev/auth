import type { AnyRelations } from "drizzle-orm";
import type { EffectMysql2Database } from "drizzle-orm/effect-mysql2";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core";

import { Database } from "./mysql-database";
import { makePasskeyTarget } from "./passkey-drivers";
import { unavailable as passkeyUnavailable } from "./passkey-state";
import { sqlClientPasskeyStandaloneGuard } from "./passkey-target";
import { mysqlTransaction } from "./transaction-mysql";

export const {
  makePasskeyCredentialServices,
  makePasskeyPersistenceServices,
  makePasskeyEnrollmentContextServices,
  makePasskeyRegistrationCeremonyServices,
  coordinatePasskeyPersistence,
  coordinatePasskeyRegistrationCeremony,
  makePasskeyManagementServices,
  makePasskeyRegistrationServices,
  coordinatePasskeyManagement,
  coordinatePasskeyRegistration,
} = makePasskeyTarget<
  Database,
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>(Database, {
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientPasskeyStandaloneGuard,
  transaction: (database, body) => mysqlTransaction(passkeyUnavailable, database, body),
});
