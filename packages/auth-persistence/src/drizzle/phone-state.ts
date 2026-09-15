import { makePhoneKernel } from "../internal/phone-kernel";
import { drizzleQueryOperations } from "./query-operations";
import { both, makeTransactionRows } from "./transaction-owner";
export { CurrentPhoneTransaction } from "../internal/phone-kernel";

export const {
  unavailable,
  equal,
  copiedRow,
  col,
  capturePhone,
  lookupPhone,
  admitPhone,
  preparePhoneMutation,
  cleanupPhoneAdmission,
} = makePhoneKernel(drizzleQueryOperations, { both, makeTransactionRows });

export const invariant: (value: unknown) => asserts value = makePhoneKernel(
  drizzleQueryOperations,
  { both, makeTransactionRows },
).invariant;
