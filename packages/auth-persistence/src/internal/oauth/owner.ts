import type { CommitJournal } from "@yielded/auth/Hooks";
import type { OAuthUnavailable } from "@yielded/auth/OAuth";
/* oxlint-disable no-explicit-any -- private adapter preserves the existing driver boundary. */
import { Context } from "effect";

import type {
  TransactionNativeDatabase,
  TransactionOwner,
  makeTransactionKernel,
} from "../transaction-kernel";
import { unavailable } from "./state";
export type { Observation, Row } from "../transaction-kernel";

export type OAuthOwner = TransactionOwner<OAuthUnavailable>;

export class CurrentOAuthTransaction extends Context.Service<CurrentOAuthTransaction, OAuthOwner>()(
  "effect-auth/persistence/CurrentOAuthTransaction",
) {}

export type OAuthNativeDatabase = TransactionNativeDatabase;

export const makeOAuthOwnerKernel = (
  transactions: Pick<
    ReturnType<typeof makeTransactionKernel>,
    "makeTransactionOwner" | "makeTransactionRows" | "both"
  >,
) => {
  const { makeTransactionOwner, makeTransactionRows } = transactions;
  const { both } = transactions;

  const { col, equal, copiedRow, matchesNativeRow } = makeTransactionRows(unavailable);

  const makeOAuthOwner = (
    database: any,
    journal: CommitJournal,
    marker: string,
    configuration: Parameters<typeof makeTransactionOwner>[4],
  ): OAuthOwner => makeTransactionOwner(database, journal, marker, unavailable, configuration);

  return { both, col, equal, copiedRow, matchesNativeRow, makeOAuthOwner };
};
