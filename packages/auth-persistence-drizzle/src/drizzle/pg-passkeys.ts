import type { AnyRelations } from "drizzle-orm";
import type { EffectPgDatabase } from "drizzle-orm/effect-postgres";
import type { AnyPgTable } from "drizzle-orm/pg-core";

import { makePasskeyTarget } from "./passkey-drivers";
import { sqlClientPasskeyStandaloneGuard } from "./passkey-target";
import { Database } from "./pg-database";

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
} = makePasskeyTarget<Database, EffectPgDatabase<AnyRelations>, AnyPgTable<{ dialect: "pg" }>>(
  Database,
  {
    mode: "interactive",
    dialect: "pg",
    locking: true,
    standaloneGuard: sqlClientPasskeyStandaloneGuard,
  },
);
