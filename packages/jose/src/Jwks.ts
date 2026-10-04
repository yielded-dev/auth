import type { Signature } from "@yielded/crypto/Signature";
import {
  Clock,
  Context,
  Deferred,
  Effect,
  Exit,
  Layer,
  Option,
  Schema,
  Scope,
  Semaphore,
  Stream,
} from "effect";
import { FetchHttpClient, HttpClient } from "effect/http";

import { AmbiguousKey, InvalidKey, JwksUnavailable, KeyNotFound, type KeyError } from "./Errors";
import { json } from "./internal/encoding";
import * as KeyInput from "./internal/keyInput";
import { AsymmetricAlgorithm, importPublic, type PublicKey, PublicJwk } from "./Jwk";

export const KeySet = Schema.Struct({
  keys: Schema.Array(PublicJwk).check(Schema.isMaxLength(256)),
});

export type KeySet = typeof KeySet.Type;

export const Selection = Schema.Struct({
  algorithm: AsymmetricAlgorithm,
  kid: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
});

export type Selection = typeof Selection.Type;

export class Jwks extends Context.Service<
  Jwks,
  {
    readonly resolve: (selection: Selection) => Effect.Effect<PublicKey, KeyError, Signature>;
  }
>()("@yielded/jose/Jwks") {}

/** One immutable public key set; local selection never requires HttpClient. */
export const layerLocal = (input: unknown): Layer.Layer<Jwks, InvalidKey> =>
  Layer.effect(
    Jwks,
    Effect.gen(function* () {
      const set = yield* readSet(input);

      return Jwks.of({
        resolve: Effect.fnUntraced(function* (input) {
          const selection = yield* readSelection(input);

          return yield* importPublic(yield* select(set, selection), selection.algorithm);
        }),
      });
    }),
  );

export interface RemoteOptions {
  /** Trusted application configuration, never a URL from a token. HTTPS only. */
  readonly url: string;
  readonly cacheTimeMs?: number;
  readonly cooldownMs?: number;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly maxKeys?: number;
  readonly maxWaiters?: number;
}

const readSet = (input: unknown) =>
  Effect.suspend(() =>
    Schema.decodeUnknownEffect(KeySet)(KeyInput.keySet(input), { reportInput: false }),
  ).pipe(
    Effect.map((set) => {
      for (const key of set.keys) {
        KeyInput.detach(key);
        if (key.key_ops !== undefined) Object.freeze(key.key_ops);
        Object.freeze(key);
      }
      Object.freeze(set.keys);

      return Object.freeze(KeyInput.detach(set));
    }),
    Effect.mapError(() => InvalidKey.make({})),
    Effect.catchDefect(() => InvalidKey.make({})),
  );

const readSelection = (input: Selection) =>
  Effect.suspend(() =>
    Schema.decodeUnknownEffect(Selection)(KeyInput.object(input), { reportInput: false }),
  ).pipe(
    Effect.map(KeyInput.detach),
    Effect.mapError(() => InvalidKey.make({})),
    Effect.catchDefect(() => InvalidKey.make({})),
  );

const select = Effect.fnUntraced(function* (set: KeySet, selection: Selection) {
  const candidates = set.keys.filter(
    (key) =>
      (selection.kid === undefined || key.kid === selection.kid) &&
      (key.alg === undefined || key.alg === selection.algorithm) &&
      (key.use === undefined || key.use === "sig") &&
      (key.key_ops === undefined || key.key_ops.includes("verify")) &&
      (selection.algorithm === "ES256"
        ? key.kty === "EC"
        : selection.algorithm === "EdDSA"
          ? key.kty === "OKP"
          : key.kty === "RSA"),
  );

  if (candidates.length === 0) return yield* KeyNotFound.make({});
  if (candidates.length !== 1) return yield* AmbiguousKey.make({});

  return candidates[0];
});

const bounded = (minimum: number, maximum: number) =>
  Schema.Int.check(Schema.isBetween({ minimum, maximum }));

const RemoteConfiguration = Schema.Struct({
  url: Schema.URLFromString.check(
    Schema.makeFilter(
      (url) =>
        url.protocol === "https:" && url.username === "" && url.password === "" && url.hash === "",
    ),
  ),
  cacheTimeMs: bounded(1, 86400000),
  cooldownMs: bounded(0, 3600000),
  timeoutMs: bounded(1, 60000),
  maxResponseBytes: bounded(1, 1048576),
  maxKeys: bounded(1, 256),
  maxWaiters: bounded(1, 1024),
});

interface Snapshot {
  readonly keys: KeySet;
  readonly expiresAt: number;
}

/**
 * One trusted HTTPS endpoint per Layer. The supplied client owns egress policy
 * and must not follow redirects; FetchHttpClient is configured to reject them.
 * Responses from another URL are rejected with every client. No stale-on-error
 * fallback, global cache, background polling, or token-supplied key URLs.
 */
export const layerRemote = (
  input: RemoteOptions,
): Layer.Layer<Jwks, JwksUnavailable, HttpClient.HttpClient> => {
  const configuration = {
    cacheTimeMs: 600000,
    cooldownMs: 30000,
    timeoutMs: 5000,
    maxResponseBytes: 131072,
    maxKeys: 64,
    maxWaiters: 64,
    ...input,
  };

  return Layer.effect(
    Jwks,
    Effect.gen(function* () {
      const options = yield* Schema.decodeUnknownEffect(RemoteConfiguration)(configuration, {
        reportInput: false,
      }).pipe(Effect.mapError(() => JwksUnavailable.make({ reason: "configuration" })));

      const client = HttpClient.withScope(yield* HttpClient.HttpClient);
      let cache: Snapshot | undefined;
      let pending: Deferred.Deferred<Snapshot, JwksUnavailable> | undefined;
      let lastAttempt = -Infinity;
      let closed = false;
      const permits = yield* Semaphore.make(options.maxWaiters);

      const scope = yield* Effect.acquireRelease(Scope.make(), (scope) =>
        Effect.gen(function* () {
          closed = true;
          cache = undefined;
          // A scoped fiber can be interrupted before its first instruction, so
          // its onExit handler alone cannot release pending lookup waiters.
          if (pending !== undefined)
            yield* Deferred.fail(pending, JwksUnavailable.make({ reason: "closed" }));
          yield* Scope.close(scope, Exit.void);
        }),
      );

      const fetch = Effect.gen(function* () {
        const response = yield* client.get(options.url.href, {
          headers: { accept: "application/json" },
        });

        if (response.status !== 200 || response.url !== options.url.href)
          return yield* JwksUnavailable.make({ reason: "response" });
        const buffer = new Uint8Array(options.maxResponseBytes);

        const length = yield* Stream.runFoldEffect(
          response.stream,
          () => 0,
          (length, chunk) => {
            if (chunk.byteLength > buffer.length - length)
              return Effect.fail(JwksUnavailable.make({ reason: "response" }));
            buffer.set(chunk, length);

            return Effect.succeed(length + chunk.length);
          },
        );

        const document = yield* json(buffer.subarray(0, length), "payload");
        const keys = yield* readSet(document);

        if (keys.keys.length > options.maxKeys)
          return yield* JwksUnavailable.make({ reason: "response" });

        return {
          keys,
          expiresAt: (yield* Clock.currentTimeMillis) + options.cacheTimeMs,
        } satisfies Snapshot;
      }).pipe(
        Effect.scoped,
        Effect.provideService(FetchHttpClient.RequestInit, {
          redirect: "error",
          credentials: "omit",
        }),
        Effect.catchTag("HttpClientError", () => JwksUnavailable.make({ reason: "transport" })),
        Effect.catchTag(["JoseInvalidToken", "JoseInvalidKey"], () =>
          JwksUnavailable.make({ reason: "response" }),
        ),
        Effect.timeoutOrElse({
          duration: options.timeoutMs,
          orElse: () => JwksUnavailable.make({ reason: "transport" }),
        }),
      );

      const refresh = Effect.uninterruptibleMask((restore) =>
        Effect.gen(function* () {
          if (closed) return yield* JwksUnavailable.make({ reason: "closed" });
          if (pending !== undefined) return yield* restore(Deferred.await(pending));
          const now = yield* Clock.currentTimeMillis;

          if (now - lastAttempt < options.cooldownMs)
            return yield* JwksUnavailable.make({ reason: "cooldown" });
          lastAttempt = now;
          const result = yield* Deferred.make<Snapshot, JwksUnavailable>();

          pending = result;
          yield* fetch.pipe(
            Effect.onExit((exit) =>
              Effect.gen(function* () {
                if (Exit.isSuccess(exit) && !closed) cache = exit.value;
                pending = undefined;
                yield* Deferred.done(result, exit);
              }),
            ),
            Effect.forkIn(scope, { uninterruptible: false }),
          );

          return yield* restore(Deferred.await(result));
        }),
      );

      const resolve = Effect.fnUntraced(function* (input: Selection) {
        if (closed) return yield* JwksUnavailable.make({ reason: "closed" });
        const selection = yield* readSelection(input);
        const now = yield* Clock.currentTimeMillis;
        const current = cache !== undefined && cache.expiresAt > now ? cache : yield* refresh;

        const candidate = yield* select(current.keys, selection).pipe(
          Effect.catchTag("JoseKeyNotFound", () =>
            Effect.gen(function* () {
              if ((yield* Clock.currentTimeMillis) - lastAttempt < options.cooldownMs)
                return yield* KeyNotFound.make({});

              return yield* select((yield* refresh).keys, selection);
            }),
          ),
        );

        return yield* importPublic(candidate, selection.algorithm);
      });

      return Jwks.of({
        resolve: (selection) =>
          resolve(selection).pipe(
            permits.withPermitsIfAvailable(1),
            Effect.flatMap(
              Option.match({
                onNone: () => JwksUnavailable.make({ reason: "busy" }),
                onSome: Effect.succeed,
              }),
            ),
          ),
      });
    }),
  );
};
