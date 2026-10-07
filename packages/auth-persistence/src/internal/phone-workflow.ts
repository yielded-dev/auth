import { coordinateCommit, hasCommitScope, LifecycleHooks } from "@yielded/auth/Hooks";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import { PhoneAdmission, PhoneOtpUnavailable, PhoneSignInTargets } from "@yielded/auth/PhoneOtp";
import { Cause, Context, Effect, Schema } from "effect";

import type { PersistenceOwner } from "./persistence-owner";
import type { PhoneStore } from "./phone-store";

export const makePhoneWorkflow = Effect.fnUntraced(function* (
  owner: Pick<PersistenceOwner<PhoneStore>, "transaction">,
  modules: ReadonlyArray<string>,
  standalone: Effect.Effect<void, PhoneOtpUnavailable>,
) {
  const hooks = yield* LifecycleHooks;
  const unavailable = () => PhoneOtpUnavailable.make({});

  const run = <A, E, R>(moduleId: string, body: (store: PhoneStore) => Effect.Effect<A, E, R>) =>
    Effect.gen(function* () {
      if (!modules.includes(moduleId) || (yield* hasCommitScope)) return yield* unavailable();
      yield* standalone;

      return (yield* coordinateCommit(() => owner.transaction(body))).value;
    }).pipe(
      Effect.provideService(LifecycleHooks, hooks),
      (operation) => reportPersistenceFailure(operation, Schema.is(PhoneOtpUnavailable)),
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))),
      Effect.catchDefect(() => Effect.fail(unavailable())),
    );

  return Context.make(PhoneAdmission, {
    admit: (input) => run(input.moduleId, (store) => store.admit(input)),
    cleanup: (input) => run(input.moduleId, (store) => store.cleanup(input)),
  }).pipe(
    Context.add(PhoneSignInTargets, {
      lookup: (input) => run(input.moduleId, (store) => store.lookup(input)),
    }),
  );
});
