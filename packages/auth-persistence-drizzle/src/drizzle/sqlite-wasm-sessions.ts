import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";

import { sqlClientSessionStandaloneGuard } from "./session-target";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./sqlite-sessions";
import { Database } from "./sqlite-wasm-database";

export const {
  coordinateAuthenticationAuthority,
  coordinatePendingAuthentication,
  coordinateSignedSessionValidity,
  coordinateStatefulSessions,
  makeAuthenticationAuthorityServices,
  makePendingAuthenticationServices,
  makeSessionStepUpServices,
  coordinateSessionStepUp,
  makeSignedSessionValidityServices,
  makeStatefulSessionServices,
} = makeSqliteSessionTarget<Database, EffectSQLiteWasmDatabase<AnyRelations>>(Database, (service) =>
  sqliteSessionConfiguration("interactive", sqlClientSessionStandaloneGuard(service)),
);
