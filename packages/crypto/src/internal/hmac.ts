import { Effect, Exit, Fiber, Redacted, Schema, Scope } from "effect";

import { CryptoUnavailable } from "../Errors";
import { Hmac, Input, type Key, KeyInput, VerifyInput } from "../Hmac";
import { copy, decode, importError, nativeError, withSecret } from "./common";

const keyBytes = Schema.Uint8Array.check(Schema.isMinLength(1));

export const makeHmac = (subtle: SubtleCrypto): Hmac["Service"] => {
  const importKey = Effect.fnUntraced(function* (input: KeyInput) {
    const value = yield* decode(KeyInput, input, "key");

    yield* decode(keyBytes, Redacted.value(value.key), "key");

    // A sequential child joins every native call before dropping the key, even
    // when the caller's Scope runs its other finalizers in parallel.
    const scope = yield* Scope.fork(yield* Effect.scope, "sequential");
    let imported: CryptoKey | undefined;

    yield* Scope.addFinalizer(
      scope,
      Effect.sync(() => {
        imported = undefined;
      }),
    );

    const available = Effect.suspend(() =>
      scope.state._tag === "Closed" ? Effect.fail(CryptoUnavailable.make({})) : Effect.void,
    );

    const run = <A, E>(operation: Effect.Effect<A, E>) =>
      Effect.acquireUseRelease(
        available.pipe(Effect.andThen(Effect.forkIn(operation, scope, { uninterruptible: false }))),
        (fiber) =>
          Effect.gen(function* () {
            const exit = yield* Fiber.await(fiber);

            yield* available;

            return yield* exit;
          }),
        Fiber.interrupt,
      );

    yield* run(
      withSecret(value.key, (material) =>
        Effect.tryPromise({
          try: () =>
            subtle.importKey("raw", material, { name: "HMAC", hash: value.algorithm }, false, [
              "sign",
              "verify",
            ]),
          catch: importError,
        }).pipe(
          Effect.tap((key) =>
            Effect.sync(() => {
              imported = key;
            }),
          ),
          Effect.uninterruptible,
        ),
      ),
    ).pipe(
      Effect.onExit((exit) => (Exit.isFailure(exit) ? Scope.close(scope, exit) : Effect.void)),
    );

    const use = <A>(operation: (key: CryptoKey) => Promise<A>) =>
      run(
        Effect.suspend(() => {
          const key = imported;

          return key === undefined
            ? Effect.fail(CryptoUnavailable.make({}))
            : Effect.tryPromise({ try: () => operation(key), catch: nativeError });
        }).pipe(Effect.uninterruptible),
      );

    return {
      sign: Effect.fnUntraced(function* (input) {
        const data = yield* decode(Schema.Uint8Array, input, "data").pipe(Effect.flatMap(copy));

        return new Uint8Array(yield* use((key) => subtle.sign("HMAC", key, data)));
      }),
      verify: Effect.fnUntraced(function* (input, signature) {
        const data = yield* decode(Schema.Uint8Array, input, "data").pipe(Effect.flatMap(copy));
        const tag = yield* decode(Schema.Uint8Array, signature, "data").pipe(Effect.flatMap(copy));

        return yield* use((key) => subtle.verify("HMAC", key, tag, data));
      }),
    } satisfies Key;
  });

  return Hmac.of({
    importKey,
    sign: Effect.fnUntraced(function* (input) {
      const value = yield* decode(Input, input, "data");
      const data = yield* copy(value.data);
      const key = yield* importKey(value);

      return yield* key.sign(data);
    }, Effect.scoped),
    verify: Effect.fnUntraced(function* (input) {
      const value = yield* decode(VerifyInput, input, "data");
      const data = yield* copy(value.data);
      const tag = yield* copy(value.tag);
      const key = yield* importKey(value);

      return yield* key.verify(data, tag);
    }, Effect.scoped),
  });
};
