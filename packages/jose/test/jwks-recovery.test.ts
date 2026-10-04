import { it } from "@effect/vitest";
import { Jwks, Jws } from "@yielded/jose";
import { Context, Deferred, Effect, Exit, Fiber, Layer, Redacted, Scheduler, Scope } from "effect";
import { HttpClient, HttpClientError, HttpClientResponse } from "effect/http";
import { TestClock } from "effect/testing";
import * as jose from "jose";
import { expect } from "vite-plus/test";

import { cryptoLayer, privateJwk, publicJwk, utf8 } from "./fixtures";

// Selection/snapshot and failed-response cases adapt panva/jose's
// test/jwks/{local,remote}.test.ts. Effect-specific lifetime cases exercise the
// public service with controlled external HTTP, without mocking its cache.
it.effect("rejects malformed local sets while allowing an empty set", () =>
  Effect.gen(function* () {
    for (const input of [
      null,
      {},
      { keys: null },
      { keys: [null] },
      { keys: Array(1) },
      { keys: [{ ...publicJwk, use: 0 }] },
      { keys: [{ ...publicJwk, key_ops: ["verify", 0] }] },
    ]) {
      expect(
        (yield* Jwks.Jwks.pipe(Effect.provide(Jwks.layerLocal(input)), Effect.flip))._tag,
      ).toBe("JoseInvalidKey");
    }
    const empty = yield* Jwks.Jwks.pipe(Effect.provide(Jwks.layerLocal({ keys: [] })));

    expect((yield* empty.resolve({ algorithm: "ES256" }).pipe(Effect.flip))._tag).toBe(
      "JoseKeyNotFound",
    );
  }).pipe(Effect.provide(cryptoLayer)),
);

it.effect("captures local key-set authority without freezing the caller's input", () =>
  Effect.gen(function* () {
    const input = { keys: [{ ...publicJwk, kid: "original", key_ops: ["verify"] }] };
    const set = yield* Jwks.Jwks.pipe(Effect.provide(Jwks.layerLocal(input)));

    input.keys[0].kid = "changed";
    input.keys[0].key_ops[0] = "sign";
    input.keys.length = 0;
    expect((yield* set.resolve({ algorithm: "ES256", kid: "original" })).jwk).toEqual({
      ...publicJwk,
      kid: "original",
      key_ops: ["verify"],
    });
    expect(
      (yield* set.resolve({ algorithm: "ES256", kid: "changed" }).pipe(Effect.flip))._tag,
    ).toBe("JoseKeyNotFound");
  }).pipe(Effect.provide(cryptoLayer)),
);

it.effect("does not select a key by inherited metadata", () =>
  Effect.gen(function* () {
    const key = { ...publicJwk };

    Object.setPrototypeOf(key, { kid: "inherited" });
    const set = yield* Jwks.Jwks.pipe(Effect.provide(Jwks.layerLocal({ keys: [key] })));

    expect(
      (yield* set.resolve({ algorithm: "ES256", kid: "inherited" }).pipe(Effect.flip))._tag,
    ).toBe("JoseKeyNotFound");
    expect((yield* set.resolve({ algorithm: "ES256" })).jwk).toEqual(publicJwk);
  }).pipe(Effect.provide(cryptoLayer)),
);

it.effect("keeps captured key selection independent of later prototype changes", () =>
  Effect.gen(function* () {
    const set = yield* Jwks.Jwks.pipe(Effect.provide(Jwks.layerLocal({ keys: [publicJwk] })));
    const previous = Object.getOwnPropertyDescriptor(Object.prototype, "kid");

    yield* Effect.acquireRelease(
      Effect.sync(() =>
        Object.defineProperty(Object.prototype, "kid", {
          value: "inherited-later",
          writable: true,
          configurable: true,
        }),
      ),
      () =>
        Effect.sync(() => {
          if (previous === undefined) Reflect.deleteProperty(Object.prototype, "kid");
          else Object.defineProperty(Object.prototype, "kid", previous);
        }),
    );
    expect(
      (yield* set.resolve({ algorithm: "ES256", kid: "inherited-later" }).pipe(Effect.flip))._tag,
    ).toBe("JoseKeyNotFound");
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect("does not import keys supplied by an inherited array slot", () =>
  Effect.gen(function* () {
    const keys: Array<unknown> = [];

    keys.length = 1;
    Object.setPrototypeOf(keys, [publicJwk]);
    expect(
      (yield* Jwks.Jwks.pipe(Effect.provide(Jwks.layerLocal({ keys })), Effect.flip))._tag,
    ).toBe("JoseInvalidKey");
  }).pipe(Effect.provide(cryptoLayer)),
);

it.effect("captures set and key metadata getters once before key selection", () =>
  Effect.gen(function* () {
    let sets = 0;
    let kids = 0;
    let operations = 0;

    const input = {
      get keys() {
        sets++;

        return [
          {
            ...publicJwk,
            get kid() {
              return kids++ === 0 ? "one" : "changed";
            },
            get key_ops() {
              return operations++ === 0 ? ["verify"] : ["sign"];
            },
          },
        ];
      },
    };

    const set = yield* Jwks.Jwks.pipe(Effect.provide(Jwks.layerLocal(input)));

    expect((yield* set.resolve({ algorithm: "ES256", kid: "one" })).jwk.kid).toBe("one");
    expect([sets, kids, operations]).toEqual([1, 1, 1]);
    expect(
      (yield* Jwks.Jwks.pipe(
        Effect.provide(
          Jwks.layerLocal({
            keys: [
              {
                ...publicJwk,
                get kid() {
                  throw undefined;
                },
              },
            ],
          }),
        ),
        Effect.flip,
      ))._tag,
    ).toBe("JoseInvalidKey");
  }).pipe(Effect.provide(cryptoLayer)),
);

it.effect("selects each asymmetric algorithm by key family even when kids overlap", () =>
  Effect.gen(function* () {
    const rsa = yield* Effect.promise(() => jose.generateKeyPair("RS256", { extractable: true }));
    const rsaPrivate = yield* Effect.promise(() => jose.exportJWK(rsa.privateKey));
    const rsaPublic = yield* Effect.promise(() => jose.exportJWK(rsa.publicKey));
    const ed = yield* Effect.promise(() => jose.generateKeyPair("EdDSA", { extractable: true }));
    const edPrivate = yield* Effect.promise(() => jose.exportJWK(ed.privateKey));
    const edPublic = yield* Effect.promise(() => jose.exportJWK(ed.publicKey));
    const keys = [rsaPublic, edPublic, publicJwk].map((key) => ({ ...key, kid: "shared" }));

    for (const [algorithm, jwk] of [
      ["RS256", rsaPrivate],
      ["PS256", rsaPrivate],
      ["ES256", privateJwk],
      ["EdDSA", edPrivate],
    ] as const) {
      const signing = yield* Effect.promise(() => jose.importJWK(jwk, algorithm));

      const token = yield* Effect.promise(() =>
        new jose.CompactSign(utf8(algorithm))
          .setProtectedHeader({ alg: algorithm, kid: "shared" })
          .sign(signing),
      );

      const verified = yield* Jws.verifyWithKeySet(Redacted.make(token), {
        algorithms: [algorithm],
      }).pipe(Effect.provide(Jwks.layerLocal({ keys })));

      expect(Redacted.value(verified.payload)).toEqual(utf8(algorithm));
    }
  }).pipe(Effect.provide(cryptoLayer)),
);

it.effect.each([
  { failure: "transport", reason: "transport" },
  { failure: "status", reason: "response" },
  { failure: "JSON", reason: "response" },
  { failure: "key set", reason: "response" },
])("recovers from a shared $failure failure without serving expired keys", ({ failure, reason }) =>
  Effect.gen(function* () {
    let requests = 0;
    let failing = true;
    const entered = yield* Deferred.make<void>();
    const release = yield* Deferred.make<void>();
    const document = JSON.stringify({ keys: [{ ...publicJwk, kid: "one" }] });

    const client = HttpClient.make((request) =>
      Effect.gen(function* () {
        requests++;
        if (requests > 1 && failing) {
          yield* Deferred.succeed(entered, undefined);
          yield* Deferred.await(release);
          if (failure === "transport") {
            return yield* new HttpClientError.HttpClientError({
              reason: new HttpClientError.TransportError({
                request,
                cause: "private-transport-canary",
              }),
            });
          }

          return HttpClientResponse.fromWeb(
            request,
            new Response(
              failure === "JSON" ? "{" : failure === "key set" ? '{"keys":null}' : document,
              { status: failure === "status" ? 503 : 200 },
            ),
          );
        }

        return HttpClientResponse.fromWeb(request, new Response(document));
      }),
    );

    const context = yield* Layer.build(
      Jwks.layerRemote({
        url: "https://issuer.example/keys",
        cacheTimeMs: 100,
        cooldownMs: 10,
      }).pipe(Layer.provide(Layer.succeed(HttpClient.HttpClient, client))),
    );

    const set = Context.get(context, Jwks.Jwks);

    expect((yield* set.resolve({ algorithm: "ES256", kid: "one" })).jwk.kid).toBe("one");
    yield* TestClock.adjust(99);
    expect((yield* set.resolve({ algorithm: "ES256", kid: "one" })).jwk.kid).toBe("one");
    expect(requests).toBe(1);
    yield* TestClock.adjust(1);

    const first = yield* Effect.forkChild(
      set.resolve({ algorithm: "ES256", kid: "one" }).pipe(Effect.flip),
      { startImmediately: true },
    );

    const second = yield* Effect.forkChild(
      set.resolve({ algorithm: "ES256", kid: "one" }).pipe(Effect.flip),
      { startImmediately: true },
    );

    yield* Deferred.await(entered);
    yield* Deferred.succeed(release, undefined);
    const error = yield* Fiber.join(first);

    expect(error).toMatchObject({ _tag: "JoseJwksUnavailable", reason });
    expect(yield* Fiber.join(second)).toMatchObject({ _tag: "JoseJwksUnavailable", reason });
    expect(JSON.stringify(error)).not.toContain("private-transport-canary");
    expect(requests).toBe(2);
    expect(yield* set.resolve({ algorithm: "ES256", kid: "one" }).pipe(Effect.flip)).toMatchObject({
      _tag: "JoseJwksUnavailable",
      reason: "cooldown",
    });
    expect(requests).toBe(2);
    failing = false;
    yield* TestClock.adjust(10);
    expect((yield* set.resolve({ algorithm: "ES256", kid: "one" })).jwk.kid).toBe("one");
    expect(requests).toBe(3);
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect("bounds waiters and lets one cancel without interrupting the shared refresh", () =>
  Effect.gen(function* () {
    let requests = 0;
    let interrupted = false;
    const entered = yield* Deferred.make<void>();
    const release = yield* Deferred.make<void>();

    const client = HttpClient.make((request) =>
      Effect.gen(function* () {
        requests++;
        yield* Deferred.succeed(entered, undefined);
        yield* Deferred.await(release);

        return HttpClientResponse.fromWeb(
          request,
          new Response(JSON.stringify({ keys: [publicJwk] })),
        );
      }).pipe(
        Effect.onInterrupt(() =>
          Effect.sync(() => {
            interrupted = true;
          }),
        ),
      ),
    );

    const context = yield* Layer.build(
      Jwks.layerRemote({
        url: "https://issuer.example/keys",
        maxWaiters: 2,
      }).pipe(Layer.provide(Layer.succeed(HttpClient.HttpClient, client))),
    );

    const set = Context.get(context, Jwks.Jwks);

    const first = yield* Effect.forkChild(set.resolve({ algorithm: "ES256" }), {
      startImmediately: true,
    });

    const second = yield* Effect.forkChild(set.resolve({ algorithm: "ES256" }), {
      startImmediately: true,
    });

    yield* Deferred.await(entered);
    expect(yield* set.resolve({ algorithm: "ES256" }).pipe(Effect.flip)).toMatchObject({
      _tag: "JoseJwksUnavailable",
      reason: "busy",
    });
    yield* Fiber.interrupt(first);
    expect(interrupted).toBe(false);

    const replacement = yield* Effect.forkChild(set.resolve({ algorithm: "ES256" }), {
      startImmediately: true,
    });

    yield* Deferred.succeed(release, undefined);
    expect((yield* Fiber.join(second)).jwk).toEqual(publicJwk);
    expect((yield* Fiber.join(replacement)).jwk).toEqual(publicJwk);
    expect((yield* set.resolve({ algorithm: "ES256" })).jwk).toEqual(publicJwk);
    expect(requests).toBe(1);
    expect(interrupted).toBe(false);
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

// Retains the original shutdown race: onExit cannot release a waiter if the
// refresh fiber was interrupted before it began executing.
it.effect("releases lookup waiters when the Scope closes before refresh starts", () =>
  Effect.gen(function* () {
    let requests = 0;

    const client = HttpClient.make(() =>
      Effect.sync(() => {
        requests++;
      }).pipe(Effect.andThen(Effect.never)),
    );

    const scope = yield* Effect.acquireRelease(Scope.make(), (scope) =>
      Scope.close(scope, Exit.void),
    );

    const context = yield* Layer.buildWithScope(
      Jwks.layerRemote({ url: "https://issuer.example/keys" }).pipe(
        Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
      ),
      scope,
    );

    const set = Context.get(context, Jwks.Jwks);

    const lookup = yield* Effect.forkChild(set.resolve({ algorithm: "ES256" }).pipe(Effect.flip), {
      startImmediately: true,
    });

    expect(requests).toBe(0);
    yield* Scope.close(scope, Exit.void);
    expect(yield* Fiber.join(lookup)).toMatchObject({
      _tag: "JoseJwksUnavailable",
      reason: "closed",
    });
    expect(requests).toBe(0);
  }).pipe(
    Effect.provideService(Scheduler.PreventSchedulerYield, true),
    Effect.provide(cryptoLayer),
  ),
);

it.effect("enforces the response-byte limit across chunks, accepting the exact bound", () =>
  Effect.gen(function* () {
    const document = utf8(JSON.stringify({ keys: [publicJwk] }));

    for (const overflow of [false, true]) {
      const client = HttpClient.make((request) =>
        Effect.sync(() =>
          HttpClientResponse.fromWeb(
            request,
            new Response(
              new ReadableStream<Uint8Array>({
                start(controller) {
                  controller.enqueue(document.subarray(0, 30));
                  controller.enqueue(document.subarray(30));
                  if (overflow) controller.enqueue(utf8(" "));
                  controller.close();
                },
              }),
            ),
          ),
        ),
      );

      const context = yield* Layer.build(
        Jwks.layerRemote({
          url: "https://issuer.example/keys",
          maxResponseBytes: document.length,
        }).pipe(Layer.provide(Layer.succeed(HttpClient.HttpClient, client))),
      );

      const result = yield* Context.get(context, Jwks.Jwks)
        .resolve({ algorithm: "ES256" })
        .pipe(
          Effect.map((key) => key.jwk),
          Effect.catchTag("JoseJwksUnavailable", (error) => Effect.succeed(error.reason)),
        );

      expect(result).toEqual(overflow ? "response" : publicJwk);
    }
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);
