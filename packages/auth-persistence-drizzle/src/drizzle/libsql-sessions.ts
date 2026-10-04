import { requireStandalone as standalone } from "@yielded/auth-persistence/Adapter";
import { SessionUnavailable } from "@yielded/auth/Sessions";
import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";

import { Database } from "./libsql-database";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./sqlite-sessions";

const requireStandaloneSession = standalone(() => SessionUnavailable.make({}));

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
} = makeSqliteSessionTarget<Database, EffectLibsqlDatabase<AnyRelations>>(
  Database,
  sqliteSessionConfiguration("interactive", requireStandaloneSession),
);
