import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";

import { sqlClientSessionStandaloneGuard } from "./session-target";
import { Database } from "./sqlite-node-database";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./sqlite-sessions";

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
} = makeSqliteSessionTarget<Database, EffectSQLiteNodeDatabase<AnyRelations>>(Database, (service) =>
  sqliteSessionConfiguration("interactive", sqlClientSessionStandaloneGuard(service)),
);
