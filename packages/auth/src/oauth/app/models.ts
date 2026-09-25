import { Context, type Effect, type Redacted, Schema } from "effect";

import type { AuthOperationResult } from "../../operations/credentials";
import type { SessionSigningKeyring } from "../../sessions/crypto";
import type { SessionInvalid } from "../../sessions/errors";
import {
  type OAuthConnectedBusy,
  type OAuthConnectedReauthorizationRequired,
  OAuthConnectedConfiguration,
  type OAuthConnectedProfile,
  OAuthConnectedSealedTokens,
  OAuthConnectedTokenContext,
} from "../connectedModels";
import type { OAuthConnectedProtocol } from "../OAuthConnectedProtocol";
import type { OAuthRejected, OAuthUnavailable } from "../signInErrors";
import { OAuthSealedTransaction, OAuthSignInTransactionContext } from "../signInModels";

/** Provider adapters bind to the exact callback owned by this application.
 * The existing connected protocol owns provider verification and token handling.
 * Secrets remain in the adapter Layer, never in the shared application contract.
 */
export interface Provider<E = never, R = never> {
  readonly configure: (callbackUrl: string) => Effect.Effect<
    {
      readonly profile: OAuthConnectedProfile;
      readonly protocol: OAuthConnectedProtocol["Service"];
    },
    E,
    R
  >;
}

export interface SessionOptions {
  readonly origin: string;
  readonly sessionKeys: SessionSigningKeyring;
}

export interface Options<E, R> extends SessionOptions {
  readonly provider: Provider<E, R>;
}

export type ConnectionReference = Pick<OAuthConnectedTokenContext, "subjectId" | "grantId">;

export interface Workflow<Session extends ConnectionReference> {
  readonly begin: (
    returnTarget?: string,
  ) => Effect.Effect<
    AuthOperationResult<{ readonly authorizationUrl: Redacted.Redacted<string> }>,
    OAuthRejected | OAuthUnavailable
  >;
  readonly complete: (
    binding: Redacted.Redacted<string>,
    response: URLSearchParams,
  ) => Effect.Effect<
    AuthOperationResult<{ readonly session: Session; readonly returnTarget: string }>,
    OAuthRejected | OAuthUnavailable | OAuthConnectedBusy
  >;
  /** Server-only capability. Obtain this reference from a verified session or
   * trusted application storage; never forward arbitrary caller-supplied IDs.
   * The callback runs once, with no automatic retry of its external work.
   */
  readonly withAccessToken: <A, E, R>(
    connection: Pick<Session, "subjectId" | "grantId">,
    use: (token: Redacted.Redacted<string>) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<
    A,
    | E
    | OAuthRejected
    | OAuthUnavailable
    | OAuthConnectedBusy
    | OAuthConnectedReauthorizationRequired,
    R
  >;
  /** Disable local API access. App sessions retain their original expiry. */
  readonly disconnect: (
    connection: Pick<Session, "subjectId" | "grantId">,
  ) => Effect.Effect<void, OAuthRejected | OAuthUnavailable | OAuthConnectedBusy>;
}

export interface SessionVerifier<Session> {
  readonly verify: (
    credential: Redacted.Redacted<string>,
  ) => Effect.Effect<Session, SessionInvalid | OAuthUnavailable>;
}

const Version = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/));

export const FlowRecord = Schema.TaggedStruct("Flow", {
  version: Version,
  /** Claiming permanently consumes the flow and discards its encrypted secrets. */
  status: Schema.Literals(["Pending", "Claimed"]),
  context: OAuthSignInTransactionContext,
  configuration: OAuthConnectedConfiguration,
  sealed: Schema.optionalKey(OAuthSealedTransaction),
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
