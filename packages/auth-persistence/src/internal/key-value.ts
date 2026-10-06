import { AtomicKeyValueStore } from "@yielded/auth/Persistence";
import { Clock, Context, Effect, Layer, Schema } from "effect";
import * as KeyValueStore from "effect/persistence/KeyValueStore";
import * as RateLimiter from "effect/persistence/RateLimiter";
import * as Redis from "effect/persistence/Redis";

import { PersistenceConfigurationError } from "./configuration";

/** One process-local storage Layer for development. Restarting loses all state;
 * missing session authority records fail closed. Reuse this Layer at the root. */
export const layerMemory = Layer.merge(
  Layer.syncContext(() => {
    const values = new Map<string, string>();

    const store = KeyValueStore.makeStringOnly({
      get: (key) => Effect.sync(() => values.get(key)),
      set: (key, value) => Effect.sync(() => void values.set(key, value)),
      remove: (key) => Effect.sync(() => void values.delete(key)),
      clear: Effect.sync(() => values.clear()),
      size: Effect.sync(() => values.size),
    });

    return Context.make(KeyValueStore.KeyValueStore, store).pipe(
      Context.add(AtomicKeyValueStore, {
        consistency: "strong",
        compareAndSet: (key, expected, value, options) =>
          Clock.clockWith((clock) =>
            Effect.sync(() => {
              if (
                values.get(key) !== expected ||
                (options?.expiresAtMillis !== undefined &&
                  clock.currentTimeMillisUnsafe() >= options.expiresAtMillis)
              )
                return false;
              values.set(key, value);

              return true;
            }),
          ),
      }),
    );
  }),
  RateLimiter.layerStoreMemory,
);

const compareAndSetScript = Redis.script(
  (
    hash: string,
    key: string,
    expected: string | undefined,
    value: string,
    expiresAtMillis?: number,
  ) => [
    hash,
    key,
    expected === undefined ? "missing" : "present",
    expected ?? "",
    value,
    expiresAtMillis === undefined ? "" : String(expiresAtMillis),
  ],
  {
    numberOfKeys: 1,
    lua: `
local current = redis.call("HGET", KEYS[1], ARGV[1])
if ARGV[2] == "missing" then
  if current then return 0 end
elseif current ~= ARGV[3] then
  return 0
end
if ARGV[5] ~= "" then
  local clock = redis.call("TIME")
  local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
  if now >= tonumber(ARGV[5]) then return 0 end
end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[4])
return 1`,
  },
).withReturnType<unknown>();

/** Root storage over one application-supplied Redis connection. KV values live in
 * an isolated hash; rate limits use Effect's atomic Redis implementation.
 * Use primary reads and durable Redis configuration for revocation authority. */
export const layerRedis = (options: { readonly prefix: string }) =>
  Layer.effectContext(
    Effect.gen(function* () {
      const prefix = yield* Schema.decodeEffect(Schema.NonEmptyString)(options.prefix).pipe(
        Effect.mapError(() => PersistenceConfigurationError.make({ reason: "key-value-prefix" })),
      );

      const redis = yield* Redis.Redis;
      const hash = `${prefix}:values`;

      const run = <A>(
        method: string,
        effect: Effect.Effect<A, Redis.RedisError | Schema.SchemaError>,
      ) =>
        effect.pipe(
          Effect.mapError(
            () =>
              new KeyValueStore.KeyValueStoreError({
                method,
                message: "Key-value storage unavailable",
              }),
          ),
        );

      const store = KeyValueStore.makeStringOnly({
        get: (key) =>
          run(
            "get",
            redis.send("HGET", hash, key).pipe(
              Effect.flatMap(Schema.decodeUnknownEffect(Schema.NullOr(Schema.String))),
              Effect.map((value) => value ?? undefined),
            ),
          ),
        set: (key, value) => run("set", redis.send("HSET", hash, key, value).pipe(Effect.asVoid)),
        remove: (key) => run("remove", redis.send("HDEL", hash, key).pipe(Effect.asVoid)),
        clear: run("clear", redis.send("DEL", hash).pipe(Effect.asVoid)),
        size: run(
          "size",
          redis.send("HLEN", hash).pipe(Effect.flatMap(Schema.decodeUnknownEffect(Schema.Natural))),
        ),
      });

      const compareAndSet = redis.eval(compareAndSetScript);
      const limiter = yield* RateLimiter.makeStoreRedis({ prefix: `${prefix}:limits:` });

      return Context.make(KeyValueStore.KeyValueStore, store).pipe(
        Context.add(AtomicKeyValueStore, {
          consistency: "strong",
          compareAndSet: (key, expected, value, options) =>
            run(
              "compareAndSet",
              compareAndSet(hash, key, expected, value, options?.expiresAtMillis).pipe(
                Effect.flatMap(Schema.decodeUnknownEffect(Schema.Literals([0, 1]))),
                Effect.map((result) => result === 1),
              ),
            ),
        }),
        Context.add(RateLimiter.RateLimiterStore, limiter),
      );
    }),
  );
