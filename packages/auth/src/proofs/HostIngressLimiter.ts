import { Context, type Effect, type Redacted } from "effect";

import type { ProofIngressDenied, ProofUnavailable } from "./errors";

/**
 * Optional host extension, invoked before RPC/HTTP parsing as well as valid calls.
 * Only the host's trusted network extraction supplies these keys; wire payloads
 * cannot choose their own IP/device bucket. No permissive default or process-
 * memory implementation is presented as distributed protection.
 */
export class HostIngressLimiter extends Context.Service<
  HostIngressLimiter,
  {
    readonly check: (input: {
      readonly action: string;
      readonly networkKey: Redacted.Redacted<string>;
      readonly deviceKey?: Redacted.Redacted<string>;
    }) => Effect.Effect<void, ProofIngressDenied | ProofUnavailable>;
  }
>()("effect-auth/HostIngressLimiter") {}
