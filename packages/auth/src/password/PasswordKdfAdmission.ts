import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import { Context, Effect, Layer } from "effect";

import { PasswordConfigurationError, PasswordKdfBusy } from "./errors";

/** Share ONE Layer instance across hashers in a runtime. This bounds actual
 * nonabortable work, not distributed guesses. Callbacks must finish only after
 * their underlying computation finishes: an already-detached Promise is unsafe.
 * Work includes allocation, derive, comparison and cleanup. Waiting is bounded
 * and interruptible; once work starts, it retains its permit through cleanup.
 */
export class PasswordKdfAdmission extends Context.Service<
  PasswordKdfAdmission,
  {
    readonly run: <A, E, R>(
      work: Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E | PasswordKdfBusy, R>;
  }
>()("effect-auth/PasswordKdfAdmission") {
  /** Both tags share one instance, including nested KDF work in the same fiber. */
  static readonly layer = (options: KdfAdmission.Options = {}) => {
    const generic = KdfAdmission.layer(options).pipe(
      Layer.catch(() =>
        Layer.effect(
          KdfAdmission.KdfAdmission,
          Effect.fail(PasswordConfigurationError.make({ component: "admission" })),
        ),
      ),
    );

    return Layer.effect(
      this,
      Effect.gen(function* () {
        const admission = yield* KdfAdmission.KdfAdmission;

        return PasswordKdfAdmission.of({
          run: <A, E, R>(work: Effect.Effect<A, E, R>) =>
            admission
              .run(work)
              .pipe(Effect.catchTag("CryptoKdfBusy", () => Effect.fail(PasswordKdfBusy.make({})))),
        });
      }),
    ).pipe(Layer.provideMerge(generic));
  };
}
