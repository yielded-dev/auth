import { Proofs } from "@yielded/auth";
import { Effect, Fiber, Layer, Queue } from "effect";

/** One queue and worker per application, shared by all proof strategies.
 * Provider acceptance is outside the response path. Work may start before the
 * response is sent; a host requiring post-response start must gate release there.
 */
export const ProofDispatchLive = Layer.effect(
  Proofs.ProofDispatchScheduler,
  Effect.gen(function* () {
    const queue = yield* Effect.acquireRelease(
      Queue.make<Effect.Effect<void>>({ capacity: 64, strategy: "dropping" }),
      (queue) => Queue.shutdown(queue),
    );

    yield* Effect.gen(function* () {
      while (true) {
        const work = yield* Queue.take(queue);

        // Isolate task interruption while keeping it inside the worker's lifetime.
        const task = yield* work.pipe(
          Effect.timeout("10 seconds"),
          Effect.catchTag("TimeoutError", () => Effect.void),
          Effect.forkChild,
        );

        yield* Fiber.await(task);
      }
    }).pipe(Effect.forkScoped);

    return Proofs.ProofDispatchScheduler.of({
      schedule: (work) =>
        Queue.offer(queue, work).pipe(
          Effect.flatMap((accepted) => (accepted ? Effect.void : Proofs.ProofUnavailable.make({}))),
        ),
    });
  }),
);
