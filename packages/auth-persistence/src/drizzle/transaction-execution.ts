import { makeTransactionExecutionKernel } from "../internal/transaction-execution-kernel";
import { makeTransactionOwner, reportTransactionFailure } from "./transaction-owner";
export type { TransactionTargetConfiguration } from "../internal/transaction-execution-kernel";
export type { TransactionCoordinatorError } from "../internal/transaction-execution-kernel";
export type { TransactionBound } from "../internal/transaction-execution-kernel";
export type { TransactionExecution } from "../internal/transaction-execution-kernel";

export const {
  sqlClientTransactionStandaloneGuard,
  makeTransactionExecution,
  coordinateTransactionOwner,
} = makeTransactionExecutionKernel({ makeTransactionOwner, reportTransactionFailure });
