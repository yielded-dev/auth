import { Context, Effect, Layer, Option, Schema, Semaphore } from "effect";

import { PasswordConfigurationError, PasswordKdfBusy } from "./errors";

/** Share ONE Layer instance across hashers in a runtime. This bounds actual
 * nonabortable work, not distributed guesses. Callbacks must finish only after
 * their underlying computation finishes: an already-detached Promise is unsafe.
 * Work includes allocation, derive, comparison and cleanup. No waiting queue.
 */
export class PasswordKdfAdmission extends Context.Service<
  PasswordKdfAdmission,
  {
    readonly run: <A, E, R>(
      work: Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E | PasswordKdfBusy, R>;
  }
>()("effect-auth/PasswordKdfAdmission") {
  static readonly layer = (options: { readonly concurrency: number } = { concurrency: 1 }) => {
    const concurrency = options.concurrency;

    return Layer.effect(
      this,
      Effect.gen(function* () {
        yield* Schema.decodeEffect(Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 32 })))(
          concurrency,
        ).pipe(Effect.mapError(() => PasswordConfigurationError.make({ component: "admission" })));
        const semaphore = yield* Semaphore.make(concurrency);

        return PasswordKdfAdmission.of({
          run: <A, E, R>(work: Effect.Effect<A, E, R>) =>
            semaphore
              .withPermitsIfAvailable(1)(Effect.uninterruptible(work))
              .pipe(
                Effect.flatMap((result) =>
                  Option.isSome(result)
                    ? Effect.succeed(result.value)
                    : Effect.fail(PasswordKdfBusy.make({})),
                ),
              ),
        });
      }),
    );
  };
}
