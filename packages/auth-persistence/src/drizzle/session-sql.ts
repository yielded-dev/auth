import { makeSessionKernel } from "../internal/session-kernel";
import { drizzleQueryOperations } from "./query-operations";
export type { SessionSqlDatabase } from "../internal/session-kernel";
export { CurrentSessionSql } from "../internal/session-kernel";
export type { SessionSqlOptions } from "../internal/session-kernel";

export const {
  makeSqlAuthenticationAuthority,
  makeSqlPendingAuthentication,
  makeSqlStatefulSessions,
  makeSqlSignedValidity,
  makeSqlSessionStepUp,
} = makeSessionKernel(drizzleQueryOperations);
