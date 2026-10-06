import { Clock, Context, Duration, Effect, Layer, Schema, Semaphore } from "effect";
import * as RateLimiter from "effect/persistence/RateLimiter";

import { defaultLayer } from "../../auth/defaults";
import { PasswordRejected, PasswordUnavailable } from "./errors";
import { PasswordAttemptPolicy } from "./policy";

const maximumKeys = 10_000;

const storeFailure = (message: string) =>
  Effect.fail(
    new RateLimiter.RateLimiterError({
      reason: new RateLimiter.RateLimitStoreError({ message }),
    }),
  );

// Each stock store owns one bucket, so dropping an expired entry also releases
// its counter. A shared stock memory store would retain every key indefinitely.
const boundedMemoryStoreLayer = Layer.effect(
  RateLimiter.RateLimiterStore,
  Effect.sync(() => {
    const entries = new Map<
      string,
      { readonly store: RateLimiter.RateLimiterStore["Service"]; expiresAt: number }
    >();

    const lock = Semaphore.makeUnsafe(1);
    const unsupported = storeFailure("Password admission supports only token consumption");

    return RateLimiter.RateLimiterStore.of({
      fixedWindow: () => unsupported,
      adaptiveConsume: () => unsupported,
      adaptiveFeedback: () => unsupported,
      tokenBucket: Effect.fnUntraced(
        function* (options) {
          if (options.allowOverflow || options.tokens !== 1) return yield* unsupported;

          let entry = entries.get(options.key);

          if (entry === undefined) {
            if (entries.size >= maximumKeys) {
              const now = yield* Clock.currentTimeMillis;

              for (const [key, candidate] of entries) {
                if (candidate.expiresAt <= now) entries.delete(key);
              }
            }
            if (entries.size >= maximumKeys) {
              return yield* storeFailure("Password admission memory capacity exhausted");
            }

            // This layer has only synchronous memory state and no resources. Build
            // it in its own short scope so expired entries retain no layer memo map.
            const store = yield* RateLimiter.RateLimiterStore.pipe(
              Effect.provide(RateLimiter.layerStoreMemory, { local: true }),
            );

            entry = { store, expiresAt: 0 };
            entries.set(options.key, entry);
          }

          const result = yield* entry.store.tokenBucket(options);
          const now = yield* Clock.currentTimeMillis;

          // Without overflow, a full idle refill window restores every token.
          // Retain the longer horizon if the host changes its budget in place.
          entry.expiresAt = Math.max(
            entry.expiresAt,
            now + Math.ceil(Duration.toMillis(options.refillRate) * options.limit),
          );

          return result;
        },
        Effect.uninterruptible,
        Semaphore.withPermit(lock),
      ),
    });
  }),
);

const rateLimiterLayer = defaultLayer(
  RateLimiter.RateLimiter,
  RateLimiter.layer.pipe(
    Layer.provide(defaultLayer(RateLimiter.RateLimiterStore, boundedMemoryStoreLayer)),
  ),
);

/** Password admission independent of credential persistence and KDF concurrency.
 * Each successful check consumes one token without refunds, including when later
 * password work fails. Buckets refill one token per windowMillis / limit; this
 * permits an initial burst and differs from a rolling-window attempt count.
 * Callers supply stable, server-derived keys and validated password policy.
 */
export class PasswordAttemptLimiter extends Context.Service<
  PasswordAttemptLimiter,
  {
    readonly check: (input: {
      readonly moduleId: string;
      readonly action: "sign-in" | "change";
      readonly scope: "action" | "identifier" | "subject";
      readonly key: string;
      readonly budget: { readonly limit: number; readonly windowMillis: number };
    }) => Effect.Effect<void, PasswordRejected | PasswordUnavailable>;
  }
>()("effect-auth/PasswordAttemptLimiter") {
  /** Uses a supplied Effect RateLimiter or RateLimiterStore before its default.
   * Default state is process-local, resets with the runtime, and holds at most
   * 10,000 keys. Entries become eligible for cleanup after a full refill window
   * without a check, including rejected checks; budget changes retain the longer
   * expiry. New-key pressure triggers cleanup. Active buckets are never evicted;
   * a full store fails with PasswordUnavailable. No cleanup fiber runs. Supply
   * shared storage for limits coordinated across servers.
   */
  static readonly layer = Layer.effect(
    this,
    Effect.gen(function* () {
      const limiter = yield* RateLimiter.RateLimiter;

      return PasswordAttemptLimiter.of({
        check: Effect.fnUntraced(function* ({ moduleId, action, scope, key, budget }) {
          const policy = yield* Schema.decodeEffect(PasswordAttemptPolicy.fields.identifier)(
            budget,
          ).pipe(Effect.mapError(() => PasswordUnavailable.make({})));

          yield* limiter
            .consume({
              key: `effect-auth:password-attempt:${JSON.stringify([moduleId, action, scope, key])}`,
              algorithm: "token-bucket",
              limit: policy.limit,
              window: Duration.millis(policy.windowMillis),
              tokens: 1,
              onExceeded: "fail",
            })
            .pipe(
              Effect.mapError((error) =>
                error.reason._tag === "RateLimitExceeded"
                  ? PasswordRejected.make({})
                  : PasswordUnavailable.make({}),
              ),
            );
        }),
      });
    }),
  ).pipe(Layer.provide(rateLimiterLayer));
}

export const defaultPasswordAttemptLimiterLayer = defaultLayer(
  PasswordAttemptLimiter,
  PasswordAttemptLimiter.layer,
);
