import { Proofs } from "@yielded/auth";
import { Effect, Layer, Option, Redacted } from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";
import * as RateLimiter from "effect/persistence/RateLimiter";

/** Loopback example policy: twenty proof requests per network per hour across
 * all purposes. Production hosts must size their policy and share its store
 * across replicas; this in-memory Layer protects only this local process.
 */
export const ProofIngressLive = Layer.effect(
  Proofs.HostIngressLimiter,
  Effect.gen(function* () {
    const limiter = yield* RateLimiter.RateLimiter;

    return Proofs.HostIngressLimiter.of({
      check: ({ networkKey }) =>
        limiter
          .consume({
            key: `proof-network:${Redacted.value(networkKey)}`,
            limit: 20,
            window: "1 hour",
            onExceeded: "fail",
          })
          .pipe(
            Effect.asVoid,
            Effect.mapError((error) =>
              error.reason._tag === "RateLimitExceeded"
                ? Proofs.ProofIngressDenied.make({})
                : Proofs.ProofUnavailable.make({}),
            ),
          ),
    });
  }),
).pipe(Layer.provide(RateLimiter.layer.pipe(Layer.provide(RateLimiter.layerStoreMemory))));

/** These examples listen directly on loopback. Use the socket peer, never a
 * caller-supplied Forwarded/X-Forwarded-For header, and fail closed without it.
 * A proxy deployment must replace this with its own trusted peer extraction.
 */
export const ProofRequestMiddleware = HttpRouter.middleware<{
  provides: Proofs.ProofRequestContext;
}>()((handler) =>
  Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;

    if (Option.isNone(request.remoteAddress))
      return HttpServerResponse.empty({ status: 503, headers: { "cache-control": "no-store" } });

    return yield* handler.pipe(
      Effect.provideService(Proofs.ProofRequestContext, {
        networkKey: Redacted.make(request.remoteAddress.value),
      }),
    );
  }),
);
