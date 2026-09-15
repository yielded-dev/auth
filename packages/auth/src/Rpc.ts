import { Schema } from "effect";
import { RpcMiddleware } from "effect/unstable/rpc";

import { AuthUnavailable, Unauthorized } from "./Errors";
import type { CurrentSession } from "./internal/CurrentSession";

export const SessionRpcError = Schema.Union([Unauthorized, AuthUnavailable] as const);

/** Transport-neutral authenticated session contract for finite RPC calls. */
export class SessionRpcMiddleware extends RpcMiddleware.Service<
  SessionRpcMiddleware,
  { provides: CurrentSession }
>()("effect-auth/SessionRpcMiddleware", {
  error: SessionRpcError,
}) {}
