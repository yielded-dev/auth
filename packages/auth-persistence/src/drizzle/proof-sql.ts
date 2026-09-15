import { makeProofKernel } from "../internal/proof-kernel";
import { drizzleQueryOperations } from "./query-operations";
export type { ProofSqlQuery } from "../internal/proof-kernel";
export type { ProofSqlDatabase } from "../internal/proof-kernel";
export { CurrentProofSql } from "../internal/proof-kernel";
export type { ProofSqlConfiguration } from "../internal/proof-kernel";

export const { makeSqlProofPersistence, checkProofCompletionIn, completeProofPlanIn } =
  makeProofKernel(drizzleQueryOperations);
