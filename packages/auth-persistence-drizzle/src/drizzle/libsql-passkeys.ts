import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { Database } from "./libsql-database";
import { makePasskeyTarget } from "./passkey-drivers";
import { sqlClientPasskeyStandaloneGuard } from "./passkey-target";

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
  EffectLibsqlDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientPasskeyStandaloneGuard,
});
