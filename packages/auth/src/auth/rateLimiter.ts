import { Clock, Crypto, Duration, Effect, Layer, Schema, Semaphore } from "effect";
import { Base64Url } from "effect/encoding";
import * as KeyValueStore from "effect/persistence/KeyValueStore";
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

const Bucket = Schema.fromJsonString(
  Schema.Struct({ tokens: Schema.Finite, lastRefill: Schema.Finite }),
);

/** Auth token buckets in any Effect `KeyValueStore`, such as Workers KV or Redis.
 * Each check reads, refills, consumes and writes back one entry. That is not
 * atomic: concurrent checks and replication lag can admit a few extra requests.
 * A read, write or decode failure denies the request. An idle bucket refills to
 * full when next read, so expiry only bounds storage: give entries a TTL at least
 * as long as the longest window. Entries are keyed by a SHA-256 digest of the
 * bucket key, a fixed short length that carries no identifiers. Supports the
 * one-token buckets auth uses.
 */
export const keyValueRateLimiterStore: Layer.Layer<
  RateLimiter.RateLimiterStore,
  never,
  KeyValueStore.KeyValueStore | Crypto.Crypto
> = Layer.effect(
  RateLimiter.RateLimiterStore,
  Effect.gen(function* () {
    const store = yield* KeyValueStore.KeyValueStore;
    const crypto = yield* Crypto.Crypto;
    const unsupported = storeFailure("Auth rate limits support only one-token consumption");

    return RateLimiter.RateLimiterStore.of({
      fixedWindow: () => unsupported,
      adaptiveConsume: () => unsupported,
      adaptiveFeedback: () => unsupported,
      tokenBucket: (request) =>
        Effect.gen(function* () {
          if (request.allowOverflow || request.tokens !== 1) return yield* unsupported;
          const refillRateMillis = Duration.toMillis(request.refillRate);
          const now = yield* Clock.currentTimeMillis;

          const key = `effect-auth-rate:${Base64Url.encode(
            yield* crypto.digest("SHA-256", new TextEncoder().encode(request.key)),
          )}`;

          const stored = yield* store.get(key);

          const bucket =
            stored === undefined
              ? { tokens: request.limit, lastRefill: now }
              : { ...(yield* Schema.decodeEffect(Bucket)(stored)) };

          const before = { ...bucket };
          // Same arithmetic as Effect's memory store, persisted between checks.
          const tokensToAdd = Math.floor((now - bucket.lastRefill) / refillRateMillis);

          if (tokensToAdd > 0) {
            bucket.tokens = Math.min(request.limit, bucket.tokens + tokensToAdd);
            bucket.lastRefill += tokensToAdd * refillRateMillis;
          }
          if (bucket.tokens >= request.limit) bucket.lastRefill = now;
          const remaining = bucket.tokens - request.tokens;

          if (remaining >= 0) bucket.tokens = remaining;
          // A rejected check on an unchanged bucket writes nothing.
          if (
            stored === undefined ||
            bucket.tokens !== before.tokens ||
            bucket.lastRefill !== before.lastRefill
          )
            yield* store.set(key, yield* Schema.encodeEffect(Bucket)(bucket));

          return [remaining, Math.max(0, now - bucket.lastRefill)] as const;
        }).pipe(
          Effect.catchTags({
            KeyValueStoreError: () => storeFailure("Auth rate limit key-value store failed"),
            PlatformError: () => storeFailure("Auth rate limit key digest failed"),
            SchemaError: () => storeFailure("Auth rate limit entry is malformed"),
          }),
        ),
    });
  }),
);

/** A process-local `RateLimiter` that a supplied store never replaces. Fleet-wide
 * budgets use it: in a shared store one key per action would take every request's
 * write and let any client exhaust everyone's allowance. Per instance they shed load.
 */
export const localRateLimiter = (whenFull: "reject" | "evict") =>
  RateLimiter.make.pipe(Effect.provide(boundedMemoryStore(whenFull), { local: true }));

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
