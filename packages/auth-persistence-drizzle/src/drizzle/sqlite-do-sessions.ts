import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import { Effect } from "effect";

import { Database } from "./sqlite-do-database";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./sqlite-sessions";

/**
 * Session mutation methods and coordinate* functions must own their outermost
 * transactionSync call. The installed Drizzle driver exposes no context marker
 * for an arbitrary raw outer database.transaction call, so invoking either
 * boundary from one is unsupported and cannot be detected. Detectable Effect
 * commit scopes are rejected before writes.
 */
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
} = makeSqliteSessionTarget<Database, EffectSQLiteDoDatabase<AnyRelations>, true>(
  Database,
  sqliteSessionConfiguration("synchronous", Effect.void),
);
