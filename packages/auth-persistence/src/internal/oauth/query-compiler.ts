import { Context } from "effect";

import type { QueryOperations } from "../query-operations";
import type { makeTransactionKernel } from "../transaction-kernel";
import type { makeOAuthConnectedReferenceKernel } from "./connected-reference";

/** Adapter-owned SQL expressions and mapped-row compilation. Runtime database
 * and transaction authority remain NativeDatabase and CurrentOAuthTransaction. */
export class OAuthQueryCompiler extends Context.Service<
  OAuthQueryCompiler,
  QueryOperations &
    ReturnType<ReturnType<typeof makeTransactionKernel>["makeTransactionRows"]> &
    Pick<ReturnType<typeof makeTransactionKernel>, "both"> &
    Pick<ReturnType<typeof makeOAuthConnectedReferenceKernel>, "connectedReferenceCondition">
>()("effect-auth/persistence/OAuthQueryCompiler") {}
