import { makeTransactionKernel } from "../internal/transaction-kernel";
import { drizzleQueryOperations } from "./query-operations";
export type { Row } from "../internal/transaction-kernel";
export type { TransactionNativeDatabase } from "../internal/transaction-kernel";
export type { Observation } from "../internal/transaction-kernel";
export type { GuardedUpdate } from "../internal/transaction-kernel";
export type { TransactionOwner } from "../internal/transaction-kernel";

export const { reportTransactionFailure, both, makeTransactionRows, makeTransactionOwner } =
  makeTransactionKernel(drizzleQueryOperations);
