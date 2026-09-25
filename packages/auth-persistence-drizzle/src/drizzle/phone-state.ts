import { makePhoneKernel } from "@yielded/auth-persistence/Adapter";

import { drizzleQueryOperations } from "./query-operations";
import { both, makeTransactionRows } from "./transaction-owner";
export { CurrentPhoneTransaction } from "@yielded/auth-persistence/Adapter";

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
