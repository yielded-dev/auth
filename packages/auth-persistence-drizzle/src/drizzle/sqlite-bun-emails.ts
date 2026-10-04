import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";

import { sqlClientEmailStandaloneGuard } from "./email-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { Database } from "./sqlite-bun-database";
import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./sqlite-emails";

export const {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} = makeSqliteEmailTarget<Database, EffectSQLiteBunDatabase<AnyRelations>>(Database, (service) =>
  sqliteEmailConfiguration(
    "interactive",
    sqlClientEmailStandaloneGuard(service),
    sqlClientProofStandaloneGuard(service),
  ),
);
