import { Context, Effect, Layer, Option, Schema, Semaphore } from "effect";

import { InvalidInput, KdfBusy } from "./Errors";

export interface Options {
  readonly concurrency?: number;
  readonly maxQueued?: number;
  readonly maxWaitMilliseconds?: number;
}

/** Share one Layer across all backend instances to bound actual KDF work. */
export class KdfAdmission extends Context.Service<
  KdfAdmission,
  {
    readonly run: <A, E, R>(work: Effect.Effect<A, E, R>) => Effect.Effect<A, E | KdfBusy, R>;
  }
>()("@yielded/crypto/KdfAdmission") {}

const Configuration = Schema.Struct({
  concurrency: Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 32 })),
  maxQueued: Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 65536 })),
  maxWaitMilliseconds: Schema.Int.check(Schema.isGreaterThan(0)),
});

/**
 * Waiting is interruptible and bounded; admitted work is not detached on
 * interruption. The permit's scope covers native completion and buffer cleanup.
 * Defaults: one running derivation, sixteen waiting, five-second acquisition wait.
 */
export const layer = (options: Options = {}): Layer.Layer<KdfAdmission, InvalidInput> => {
  const snapshot = {
    concurrency: options.concurrency ?? 1,
    maxQueued: options.maxQueued ?? 16,
    maxWaitMilliseconds: options.maxWaitMilliseconds ?? 5000,
  };

  return Layer.effect(
    KdfAdmission,
    Effect.gen(function* () {
      const config = yield* Schema.decodeEffect(Configuration)(snapshot).pipe(
        Effect.mapError(() => InvalidInput.make({ reason: "parameters" })),
      );

      const active = yield* Semaphore.make(config.concurrency);
      const admitted = yield* Semaphore.make(config.concurrency + config.maxQueued);

      const acquire = Effect.acquireRelease(active.take(1), () => active.release(1), {
        interruptible: true,
      }).pipe(
        Effect.timeoutOrElse({
          duration: config.maxWaitMilliseconds,
          orElse: () => Effect.fail(KdfBusy.make({})),
        }),
      );

      return KdfAdmission.of({
        run: <A, E, R>(work: Effect.Effect<A, E, R>) =>
          admitted
            .withPermitsIfAvailable(1)(
              Effect.scoped(Effect.andThen(acquire, Effect.uninterruptible(work))),
            )
            .pipe(
              Effect.flatMap((result) =>
                Option.isSome(result)
                  ? Effect.succeed(result.value)
                  : Effect.fail(KdfBusy.make({})),
              ),
            ),
      });
    }),
  );
};
