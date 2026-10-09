import { Clock, Effect } from "effect";

import { allocate, destroy, fill, initialize, output } from "./argon2-core";
import type { Argon2 } from "./kdf";

/** Effect schedules time slices; admission remains held through buffer cleanup. */
export const argon2: Argon2 = (input) =>
  Effect.acquireUseRelease(
    Effect.sync(() => allocate(input)),
    (state) =>
      Effect.gen(function* () {
        const clock = yield* Clock.Clock;

        initialize(state, input);
        const blocks = fill(state, input);

        for (;;) {
          const started = clock.monotonicTimeNanosUnsafe();

          // Workers freeze clocks during CPU work. Cap each slice as well so
          // interruption and other fibers still get a turn on those runtimes.
          for (let processed = 0; processed < 2048; processed += 256) {
            for (let batch = 0; batch < 256; batch++) {
              if (blocks.next().done) return output(state, input);
            }
            if (clock.monotonicTimeNanosUnsafe() - started >= 8_000_000n) break;
          }
          yield* Effect.yieldNow;
        }
      }),
    (state) => Effect.sync(() => destroy(state)),
  );
