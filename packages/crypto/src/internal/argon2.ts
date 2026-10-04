import { Effect } from "effect";

import { CryptoUnavailable } from "../Errors";
import { allocate, destroy, fill, initialize, output } from "./argon2-core";
import type { Argon2 } from "./kdf";

/** Effect schedules bounded batches; admission remains held through buffer cleanup. */
export const argon2: Argon2 = (input) =>
  Effect.acquireUseRelease(
    Effect.try({ try: () => allocate(input), catch: () => CryptoUnavailable.make({}) }),
    (state) =>
      Effect.gen(function* () {
        yield* Effect.try({
          try: () => initialize(state, input),
          catch: () => CryptoUnavailable.make({}),
        });
        const blocks = fill(state, input);

        for (;;) {
          const done = yield* Effect.try({
            try: () => {
              for (let batch = 0; batch < 256; batch++) {
                if (blocks.next().done) return true;
              }

              return false;
            },
            catch: () => CryptoUnavailable.make({}),
          });

          if (done) break;
          yield* Effect.yieldNow;
        }

        return yield* Effect.try({
          try: () => output(state, input),
          catch: () => CryptoUnavailable.make({}),
        });
      }),
    (state) => Effect.sync(() => destroy(state)),
  );
