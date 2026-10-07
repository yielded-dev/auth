import { coordinateCommit, hasCommitScope, LifecycleHooks } from "@yielded/auth/Hooks";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import { PasswordUnavailable } from "@yielded/auth/Password";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import type { SubjectId } from "@yielded/auth/Schema";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { type Context, Crypto, Effect, Schema } from "effect";

import { PersistenceConfigurationError } from "./configuration";
import { randomId } from "./crypto";
import type { PersistenceOwner } from "./persistence-owner";
import type { PasswordRegistrationAuthority } from "./registration-contract";
import type { PasswordRegistrationStore } from "./registration-store";

class IdentifierTaken extends Schema.TaggedError<IdentifierTaken>()("IdentifierTaken", {}) {}

type CreateSubject = (input: {
  readonly requestId: string;
  readonly identifier: LoginIdentifier;
  readonly registration: unknown;
}) => Effect.Effect<SubjectId, PasswordUnavailable>;

/** Registration reserves the command, provisions the application's subject, and
 * creates the unverified identifier and password in one SQL transaction. Replays
 * always suppress; a public request ID never recovers a private password intent.
 */
export const makeRegistrationAuthority = Effect.fn("makeRegistrationAuthority")(function* <R>(
  owner: PersistenceOwner<PasswordRegistrationStore>,
  standalone: Effect.Effect<void, PasswordUnavailable>,
  provisioning: Context.Key<R, object>,
  strategy: string,
): Effect.fn.Return<
  PasswordRegistrationAuthority<unknown>,
  PersistenceConfigurationError,
  LifecycleHooks | Crypto.Crypto | R
> {
  const hooks = yield* LifecycleHooks;
  const crypto = yield* Crypto.Crypto;
  // Core has already decoded registration with the selected strategy's Schema;
  // the dynamic strategy table erases only that heterogeneous callback signature.
  const creators = (yield* provisioning) as Readonly<Record<string, CreateSubject>>;
  const createSubject = creators[strategy];

  if (createSubject === undefined)
    return yield* PersistenceConfigurationError.make({
      reason: `Missing subject provisioning for ${strategy}`,
    });

  return {
    register: (input, prepare) =>
      Effect.gen(function* () {
        if (yield* hasCommitScope) return yield* PasswordUnavailable.make({});
        yield* standalone;

        const receipt = { moduleId: input.moduleId, requestId: input.requestId };

        const suppress = coordinateCommit((journal) =>
          owner.transaction((store) =>
            Effect.gen(function* () {
              yield* store.reserve(receipt);

              return prepare({ _tag: "Suppressed" }, journal);
            }),
          ),
        );

        const committed = yield* coordinateCommit((journal) =>
          owner.transaction((store) =>
            Effect.gen(function* () {
              if (!(yield* store.reserve(receipt))) return prepare({ _tag: "Suppressed" }, journal);
              if (!(yield* store.identifierAvailable(input.identifier)))
                return prepare({ _tag: "Suppressed" }, journal);

              const subjectId = yield* createSubject({
                requestId: input.requestId,
                identifier: input.identifier,
                registration: input.registration,
              });

              const identifierRevision = SecurityRevision.make(yield* randomId);
              const credentialId = yield* randomId;
              const credentialRevision = SecurityRevision.make(yield* randomId);
              const verifierVersion = SecurityRevision.make(yield* randomId);

              if (
                !(yield* store.bindSubject({
                  moduleId: input.moduleId,
                  identifier: input.identifier,
                  subjectId,
                  replacement: input.replacement,
                  identifierRevision,
                  credentialId,
                  credentialRevision,
                  verifierVersion,
                }))
              )
                return yield* IdentifierTaken.make({});

              return prepare({ _tag: "Created", subjectId }, journal);
            }),
          ),
        ).pipe(Effect.catchTag("IdentifierTaken", () => suppress));

        return committed.value;
      }).pipe(
        Effect.provideService(LifecycleHooks, hooks),
        Effect.provideService(Crypto.Crypto, crypto),
        (work) => reportPersistenceFailure(work, Schema.is(PasswordUnavailable)),
        Effect.mapError(() => PasswordUnavailable.make({})),
      ),
  };
});
