import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";

import { sqlClientEmailStandaloneGuard } from "./email-target";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./sqlite-emails";
import { Database } from "./sqlite-wasm-database";

export const {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} = makeSqliteEmailTarget<Database, EffectSQLiteWasmDatabase<AnyRelations>>(Database, (service) =>
  sqliteEmailConfiguration(
    "interactive",
    sqlClientEmailStandaloneGuard(service),
    sqlClientProofStandaloneGuard(service),
  ),
);
