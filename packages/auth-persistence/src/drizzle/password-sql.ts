import { makePasswordKernel } from "../internal/password-kernel";
import { completeProofPlanIn } from "./proof-sql";
import { drizzleQueryOperations } from "./query-operations";
export type { PasswordSqlQuery } from "../internal/password-kernel";
export type { PasswordSqlDatabase } from "../internal/password-kernel";
export { CurrentPasswordSql } from "../internal/password-kernel";
export type { PasswordSqlConfiguration } from "../internal/password-kernel";

export const { makeSqlPasswordPersistence, passwordSqlKernel } = makePasswordKernel(
  drizzleQueryOperations,
  { completeProofPlanIn },
);
