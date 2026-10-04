import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";

import { sqlClientEmailStandaloneGuard } from "./email-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./sqlite-emails";
import { Database } from "./sqlite-node-database";

export const {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} = makeSqliteEmailTarget<Database, EffectSQLiteNodeDatabase<AnyRelations>>(Database, (service) =>
  sqliteEmailConfiguration(
    "interactive",
    sqlClientEmailStandaloneGuard(service),
    sqlClientProofStandaloneGuard(service),
  ),
);
