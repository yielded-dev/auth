import type { OAuthUnavailable } from "@yielded/auth/OAuth";
/* oxlint-disable no-explicit-any -- private adapter preserves the existing driver boundary. */
import { Context } from "effect";

import type { makeTransactionExecutionKernel } from "../transaction-execution-kernel";
import type { TransactionNativeDatabase, TransactionOwner } from "../transaction-kernel";
export type { Observation, Row } from "../transaction-kernel";

export type OAuthOwner = TransactionOwner<OAuthUnavailable>;

export class CurrentOAuthTransaction extends Context.Service<CurrentOAuthTransaction, OAuthOwner>()(
  "effect-auth/persistence/CurrentOAuthTransaction",
) {}

export type OAuthNativeDatabase = TransactionNativeDatabase;

/** Transaction execution is selected by the adapter; its methods retain the
 * root-database and active-owner requirements in their Effects. */
export class OAuthTransactionExecution extends Context.Service<
  OAuthTransactionExecution,
  ReturnType<typeof makeTransactionExecutionKernel>
>()("effect-auth/persistence/OAuthTransactionExecution") {}
