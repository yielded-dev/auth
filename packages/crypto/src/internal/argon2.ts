import { Effect } from "effect";

import { allocate, destroy, fill, initialize, output } from "./argon2-core";
import type { Argon2 } from "./kdf";

/** Effect schedules bounded batches; admission remains held through buffer cleanup. */
export const argon2: Argon2 = (input) =>
  Effect.acquireUseRelease(
    Effect.sync(() => allocate(input)),
    (state) =>
      Effect.gen(function* () {
        initialize(state, input);
        const blocks = fill(state, input);

        for (;;) {
          for (let batch = 0; batch < 256; batch++) {
            if (blocks.next().done) return output(state, input);
          }
          yield* Effect.yieldNow;
        }
      }),
    (state) => Effect.sync(() => destroy(state)),
  );
