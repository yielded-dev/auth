import * as Effect from "effect/Effect";
import * as Queue from "effect/Queue";
import * as Stream from "effect/Stream";
import { AppState } from "react-native";

/** Initial and subsequent foreground state for AuthAtom.make's sessionRenewal.
 * Consuming the stream owns the AppState subscription; importing it does no work. */
export const activity: Stream.Stream<boolean> = Stream.callback<boolean>(
  Effect.fnUntraced(function* (queue) {
    yield* Effect.acquireRelease(
      Effect.sync(() => {
        const subscription = AppState.addEventListener("change", (state) => {
          Queue.offerUnsafe(queue, state === "active");
        });

        Queue.offerUnsafe(queue, AppState.currentState === "active");

        return subscription;
      }),
      (subscription) => Effect.sync(() => subscription.remove()),
    );
  }),
);
