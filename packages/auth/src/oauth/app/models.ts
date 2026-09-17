import { Context, type Effect, Schema } from "effect";

import {
  OAuthConnectedConfiguration,
  OAuthConnectedSealedTokens,
  OAuthConnectedTokenContext,
} from "../connectedModels";
import type { OAuthUnavailable } from "../signInErrors";
import { OAuthSealedTransaction, OAuthSignInTransactionContext } from "../signInModels";

const Version = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/));

export const FlowRecord = Schema.TaggedStruct("Flow", {
  version: Version,
  status: Schema.Literals(["Pending", "Claimed", "Finished"]),
  context: OAuthSignInTransactionContext,
  configuration: OAuthConnectedConfiguration,
  sealed: Schema.optionalKey(OAuthSealedTransaction),
  deadlineMillis: Schema.Natural,
});

export const GrantRecord = Schema.TaggedStruct("Grant", {
  version: Version,
  status: Schema.Literals(["Active", "Refreshing", "Disconnected"]),
  /** A live claim reports Busy until this deadline. Expiry never permits reuse. */
  claimExpiresAtMillis: Schema.optionalKey(Schema.Natural),
  context: OAuthConnectedTokenContext,
  sealed: Schema.optionalKey(OAuthConnectedSealedTokens),
});

export type FlowRecord = typeof FlowRecord.Type;
export type GrantRecord = typeof GrantRecord.Type;
export const Record = Schema.Union([FlowRecord, GrantRecord]);
export type Record = typeof Record.Type;

/** Durable, linearizable storage for the managed OAuth application workflow.
 * Insert never overwrites. CAS compares the exact version and never retries an
 * ambiguous write. Confirmed writes are visible to subsequent reads. A refresh
 * claim is permanent until a confirmed settlement or a fresh authorization;
 * expiry does not permit another exchange. Only encrypted secrets cross here.
 * The namespace is an application identity, not a table name. Implementations
 * must reject ambient transactions: returning before commit is not confirmation.
 */
export class Persistence extends Context.Service<
  Persistence,
  {
    readonly get: (
      namespace: string,
      key: string,
    ) => Effect.Effect<Record | undefined, OAuthUnavailable>;
    readonly insert: (
      namespace: string,
      key: string,
      value: Record,
    ) => Effect.Effect<boolean, OAuthUnavailable>;
    readonly compareAndSet: (
      namespace: string,
      key: string,
      version: string,
      value: Record,
    ) => Effect.Effect<boolean, OAuthUnavailable>;
  }
>()("effect-auth/OAuthApp/Persistence") {}
