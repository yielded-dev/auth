import { Context, type Effect, Layer } from "effect";

import type { ProofUnavailable } from "./errors";

/** Application-owned admission for private, process-local proof delivery.
 *
 * Accept work without awaiting the provider. Bound both pending work and execution;
 * use an application Scope that outlives requests, and never create daemon fibers.
 * Every committed receipt, including suppression and replay, submits one task.
 * Reject full/closed admission with ProofUnavailable, without inspecting the task.
 *
 * Work has no remaining services or typed failures and contains no public result.
 * Keep its closure private: it contains credential material and is not an outbox
 * value. Do not serialize, inspect, log, or automatically retry it. Interruption
 * still propagates after ambiguous delivery settlement. A host that requires work
 * to start after sending the response must supply that release boundary itself.
 */
export class ProofDispatchScheduler extends Context.Service<
  ProofDispatchScheduler,
  {
    readonly schedule: (work: Effect.Effect<void>) => Effect.Effect<void, ProofUnavailable>;
  }
>()("effect-auth/ProofDispatchScheduler") {
  /** Explicit CLI/trusted-workflow fallback. Awaits provider acceptance and exposes
   * its latency; do not use for public eligibility-sensitive request handlers. */
  static readonly layerInline = Layer.succeed(this, { schedule: (work) => work });
}
