import { Clock, Duration, Effect, Layer, Semaphore } from "effect";
import * as RateLimiter from "effect/persistence/RateLimiter";

import { defaultLayer } from "./defaults";

const maximumKeys = 10_000;

const storeFailure = (message: string) =>
  Effect.fail(
    RateLimiter.RateLimiterError.make({
      reason: RateLimiter.RateLimitStoreError.make({ message }),
    }),
  );

// Each stock store owns one bucket, so dropping an entry also releases its
// counter. A shared stock memory store would retain every key indefinitely.
const boundedMemoryStore = (whenFull: "reject" | "evict") =>
  Layer.effect(
    RateLimiter.RateLimiterStore,
    Effect.sync(() => {
      // Insertion order is recency order: every check moves its key to the end.
      const entries = new Map<
        string,
        { readonly store: RateLimiter.RateLimiterStore["Service"]; expiresAt: number }
      >();

      const lock = Semaphore.makeUnsafe(1);
      const unsupported = storeFailure("Auth rate limits support only one-token consumption");

      return RateLimiter.RateLimiterStore.of({
        fixedWindow: () => unsupported,
        adaptiveConsume: () => unsupported,
        adaptiveFeedback: () => unsupported,
        tokenBucket: Effect.fnUntraced(
          function* (request) {
            if (request.allowOverflow || request.tokens !== 1) return yield* unsupported;

            let entry = entries.get(request.key);

            if (entry === undefined) {
              if (entries.size >= maximumKeys) {
                if (whenFull === "evict") {
                  for (const key of entries.keys()) {
                    entries.delete(key);
                    break;
                  }
                } else {
                  const now = yield* Clock.currentTimeMillis;

                  for (const [key, candidate] of entries) {
                    if (candidate.expiresAt <= now) entries.delete(key);
                  }
                  if (entries.size >= maximumKeys) {
                    return yield* storeFailure("Auth rate limit memory capacity exhausted");
                  }
                }
              }

              // This layer has only synchronous memory state and no resources. Build
              // it in its own short scope so dropped entries retain no layer memo map.
              const store = yield* RateLimiter.RateLimiterStore.pipe(
                Effect.provide(RateLimiter.layerStoreMemory, { local: true }),
              );

              entry = { store, expiresAt: 0 };
            } else entries.delete(request.key);
            entries.set(request.key, entry);

            const result = yield* entry.store.tokenBucket(request);
            const now = yield* Clock.currentTimeMillis;

            // Without overflow, a full idle refill window restores every token.
            // Retain the longer horizon if the host changes its budget in place.
            entry.expiresAt = Math.max(
              entry.expiresAt,
              now + Math.ceil(Duration.toMillis(request.refillRate) * request.limit),
            );

            return result;
          },
          Effect.uninterruptible,
          Semaphore.withPermit(lock),
        ),
      });
    }),
  );

/** The default `RateLimiter` for one Auth limiter: a supplied `RateLimiter` or
 * `RateLimiterStore` wins, otherwise process-local token buckets for at most
 * 10,000 keys. When a new key arrives at capacity, `reject` reclaims buckets idle
 * for a whole refill window and otherwise fails; `evict` drops the least recently
 * checked bucket, whose key later restarts with a full allowance. Each call owns
 * separate state; no cleanup fiber runs.
 */
export const boundedMemoryRateLimiter = (whenFull: "reject" | "evict") =>
  defaultLayer(
    RateLimiter.RateLimiter,
    // Not the shared `RateLimiter.layer`: Layers memoize by identity, so two
    // defaults built in one graph would capture whichever store built first.
    Layer.effect(RateLimiter.RateLimiter, RateLimiter.make).pipe(
      Layer.provide(defaultLayer(RateLimiter.RateLimiterStore, boundedMemoryStore(whenFull))),
    ),
  );
