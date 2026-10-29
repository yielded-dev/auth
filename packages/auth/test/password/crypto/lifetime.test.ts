import { it } from "@effect/vitest";
import * as Password from "@yielded/auth/Password";
import { KdfAdmission, layerKdf } from "@yielded/auth/Password";
import * as Kdf from "effect/crypto/Kdf";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as WebCrypto from "effect/crypto/WebCrypto";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Scheduler from "effect/Scheduler";
import * as TestClock from "effect/testing/TestClock";
import { expect } from "vite-plus/test";

const utf8 = (value: string) => new TextEncoder().encode(value);

// d36318f retained native-work masking around the owned portable implementation.
// Control the scheduler to request cancellation between real Argon2 batches;
// wall-clock timing cannot distinguish cancellation from completing the full KDF.
it.effect("cancels portable Argon2 at a batch boundary", () =>
  Effect.gen(function* () {
    const kdf = yield* Kdf.Kdf;
    const tasks: Array<() => void> = [];

    const scheduler: Scheduler.Scheduler = {
      executionMode: "sync",
      shouldYield: () => false,
      makeDispatcher: () => ({
        scheduleTask: (task) => tasks.push(task),
        flush: () => {
          while (tasks.length > 0) tasks.shift()!();
        },
      }),
    };

    const input = {
      password: utf8("password"),
      salt: utf8("somesalt"),
      memoryKiB: 8192,
      passes: 2,
      parallelism: 1,
      length: 32,
    };

    const derive = (memory: number, passes: number) =>
      kdf.derive(Kdf.argon2id({ memory, passes, parallelism: 1 }), input.password, {
        salt: input.salt,
        length: 32,
      });

    const fiber = yield* derive(input.memoryKiB, input.passes).pipe(
      Effect.provideService(Scheduler.Scheduler, scheduler),
      Effect.forkChild({ startImmediately: true }),
    );

    const suspended = tasks.length > 0 && fiber.pollUnsafe() === undefined;

    const interruption = yield* Fiber.interrupt(fiber).pipe(
      Effect.forkChild({ startImmediately: true }),
    );

    for (const task of tasks.splice(0)) task();
    const stoppedAtBoundary = fiber.pollUnsafe() !== undefined;

    // Finish queued work before asserting so a failing regression cannot leak it.
    while (tasks.length > 0) tasks.shift()!();
    yield* Fiber.join(interruption);
    const reused = yield* derive(8, 1);

    expect(suspended).toBe(true);
    expect(stoppedAtBoundary).toBe(true);
    expect(reused).toHaveLength(32);
  }).pipe(Effect.provide(layerKdf)),
);

// Admission must be retained until native KDF completion.
// A real backend operation is held at its nonabortable WebCrypto promise boundary;
// wall-clock KDF timing cannot reliably force this interruption window.
it.effect("holds KDF admission through interrupted native work and bounds queued callers", () =>
  Effect.gen(function* () {
    const entered = yield* Deferred.make<
      void,
      | Password.PasswordHashingUnavailable
      | Password.PasswordInputInvalid
      | Password.PasswordKdfBusy
      | Password.PasswordVerifierInvalid
    >();

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
      const hashing = yield* Password.PasswordHashing;

      const derive = () =>
        hashing.verify(
          Redacted.make("password"),
          Redacted.make(
            Password.EncodedPasswordHash.make(
              "pbkdf2-sha256$1$c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
          ),
        );

      const first = yield* derive().pipe(
        Effect.tapError((error) => Deferred.fail(entered, error)),
        Effect.forkChild,
      );

      yield* Deferred.await(entered);
      const interruption = yield* Fiber.interrupt(first).pipe(Effect.forkChild);
      const queued = yield* derive().pipe(Effect.result, Effect.forkChild);

      yield* TestClock.adjust(1);
      const overflow = yield* derive().pipe(Effect.result);

      yield* TestClock.adjust(100);
      const expired = yield* Fiber.join(queued);
      const workPending = interruption.pollUnsafe();
      const callsBeforeCompletion = calls;

      finish?.(new ArrayBuffer(32));
      yield* Fiber.join(interruption);
      const reused = yield* derive();

      expect(overflow).toMatchObject({ _tag: "Failure", failure: { _tag: "PasswordKdfBusy" } });
      expect(expired).toMatchObject({ _tag: "Failure", failure: { _tag: "PasswordKdfBusy" } });
      expect(workPending).toBeUndefined();
      expect(callsBeforeCompletion).toBe(1);
      expect(reused.matches).toBe(false);
      expect(calls).toBe(2);
    });

    yield* run.pipe(
      Effect.provide(
        Password.PasswordHashing.layer().pipe(
          Layer.provide(
            Layer.mergeAll(
              Kdf.layerWebCrypto.pipe(
                Layer.provide(
                  WebCrypto.layer({
                    subtle,
                    getRandomValues: (array) => globalThis.crypto.getRandomValues(array),
                    randomUUID: () => globalThis.crypto.randomUUID(),
                  }),
                ),
              ),
              SecureRandom.layerWebCrypto,
              KdfAdmission.layer({ concurrency: 1, maxQueued: 1, maxWaitMilliseconds: 100 }),
            ),
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

    expect(result).toMatchObject({ _tag: "PasswordConfigurationError", component: "hashing" });
  }),
);
