import { it } from "@effect/vitest";
import type { KdfBusy, OperationError } from "@yielded/crypto/Errors";
import { Kdf } from "@yielded/crypto/Kdf";
import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import * as WebCrypto from "@yielded/crypto/WebCrypto";
import { Deferred, Effect, Fiber, Layer, Redacted } from "effect";
import { TestClock } from "effect/testing";
import { expect } from "vite-plus/test";

import { utf8 } from "./backends";

// Admission must be retained until native KDF completion.
// A real backend operation is held at its nonabortable WebCrypto promise boundary;
// wall-clock KDF timing cannot reliably force this interruption window.
it.effect("holds KDF admission through interrupted native work and bounds queued callers", () =>
  Effect.gen(function* () {
    const entered = yield* Deferred.make<void, OperationError | KdfBusy>();
    let finish: ((value: ArrayBuffer) => void) | undefined;
    let calls = 0;

    const subtle = new Proxy(globalThis.crypto.subtle, {
      get(target, property) {
        if (property === "deriveBits") {
          return (...args: Parameters<SubtleCrypto["deriveBits"]>) => {
            calls++;
            if (calls !== 1) return target.deriveBits(...args);

            return new Promise<ArrayBuffer>((resolve) => {
              finish = resolve;
              Deferred.doneUnsafe(entered, Effect.void);
            });
          };
        }
        const value = Reflect.get(target, property, target);

        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    const run = Effect.gen(function* () {
      const kdf = yield* Kdf;

      const input = {
        password: Redacted.make(utf8("password")),
        salt: utf8("salt"),
        iterations: 1,
        length: 32,
      };

      const first = yield* kdf.pbkdf2(input).pipe(
        Effect.tapError((error) => Deferred.fail(entered, error)),
        Effect.forkChild,
      );

      yield* Deferred.await(entered);
      const interruption = yield* Fiber.interrupt(first).pipe(Effect.forkChild);
      const queued = yield* kdf.pbkdf2(input).pipe(Effect.result, Effect.forkChild);

      yield* TestClock.adjust(1);
      const overflow = yield* kdf.pbkdf2(input).pipe(Effect.result);

      yield* TestClock.adjust(100);
      const expired = yield* Fiber.join(queued);
      const workPending = interruption.pollUnsafe();
      const callsBeforeCompletion = calls;

      finish?.(new ArrayBuffer(32));
      yield* Fiber.join(interruption);
      const reused = yield* kdf.pbkdf2(input);

      expect(overflow).toMatchObject({ _tag: "Failure", failure: { _tag: "CryptoKdfBusy" } });
      expect(expired).toMatchObject({ _tag: "Failure", failure: { _tag: "CryptoKdfBusy" } });
      expect(workPending).toBeUndefined();
      expect(callsBeforeCompletion).toBe(1);
      expect(Redacted.value(reused)).toHaveLength(32);
      expect(calls).toBe(2);
    });

    yield* run.pipe(
      Effect.provide(
        WebCrypto.layer(subtle).pipe(
          Layer.provide(
            KdfAdmission.layer({ concurrency: 1, maxQueued: 1, maxWaitMilliseconds: 100 }),
          ),
        ),
      ),
    );
  }),
);

it.effect("rejects invalid KDF admission configuration at Layer construction", () =>
  Effect.gen(function* () {
    const result = yield* Effect.scoped(Layer.build(KdfAdmission.layer({ concurrency: 0 }))).pipe(
      Effect.flip,
    );

    expect(result).toMatchObject({ _tag: "CryptoInvalidInput", reason: "parameters" });
  }),
);
