import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";

import { sqlClientSessionStandaloneGuard } from "./session-target";
import { Database } from "./sqlite-bun-database";
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
} = makeSqliteSessionTarget<Database, EffectSQLiteBunDatabase<AnyRelations>>(Database, (service) =>
  sqliteSessionConfiguration("interactive", sqlClientSessionStandaloneGuard(service)),
);
