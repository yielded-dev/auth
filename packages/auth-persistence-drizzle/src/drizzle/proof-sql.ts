import { makeProofKernel } from "@yielded/auth-persistence/Adapter";
import type { AnyColumn, SQL } from "drizzle-orm";

import { drizzleQueryOperations } from "./query-operations";
export type { ProofSqlQuery } from "@yielded/auth-persistence/Adapter";
export type { ProofSqlDatabase } from "@yielded/auth-persistence/Adapter";
export { CurrentProofSql } from "@yielded/auth-persistence/Adapter";
export type { ProofSqlConfiguration } from "@yielded/auth-persistence/Adapter";

const kernel = makeProofKernel(drizzleQueryOperations);

export const { makeSqlProofPersistence, completeProofPlanIn } = kernel;

export const checkProofCompletionIn: ReturnType<
  typeof makeProofKernel<SQL, AnyColumn>
>["checkProofCompletionIn"] = kernel.checkProofCompletionIn;
