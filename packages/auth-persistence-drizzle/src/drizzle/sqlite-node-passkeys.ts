import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

import { makePasskeyTarget } from "./passkey-drivers";
import { sqlClientPasskeyStandaloneGuard } from "./passkey-target";
import { Database } from "./sqlite-node-database";

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
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientPasskeyStandaloneGuard,
});
