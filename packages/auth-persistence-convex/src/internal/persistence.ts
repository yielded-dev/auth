import { hasCommitScope } from "@yielded/auth/Hooks";
import { Persistence, type Record, Unavailable } from "@yielded/auth/OAuthServer";
import type { FunctionReference, GenericActionCtx, GenericDataModel } from "convex/server";
import { Context, Effect, Layer, Schema } from "effect";

import type { CompareAndSet, GrantKey, Insert } from "./models";
import { Payload } from "./models";

export interface FunctionReferences {
  readonly get: FunctionReference<"query", "internal", typeof GrantKey.Type, string | null>;
  readonly insert: FunctionReference<"mutation", "internal", typeof Insert.Type, boolean>;
  readonly compareAndSet: FunctionReference<
    "mutation",
    "internal",
    typeof CompareAndSet.Type,
    boolean
  >;
  readonly revoke: FunctionReference<"mutation", "internal", typeof GrantKey.Type, null>;
}

/** Generated internal function references from the application's Convex deployment. */
export class Functions extends Context.Service<Functions, FunctionReferences>()(
  "effect-auth/convex/Functions",
) {}

/** Provide separately for each action/HTTP action invocation. runAction deliberately
 * excludes query/mutation contexts: their nested mutations do not commit independently.
 */
export class ActionContext extends Context.Service<
  ActionContext,
  Pick<GenericActionCtx<GenericDataModel>, "runQuery" | "runMutation" | "runAction">
>()("effect-auth/convex/ActionContext") {}

const standalone = Effect.flatMap(hasCommitScope, (active) =>
  active ? Unavailable.make({}) : Effect.void,
);

const invoke = <S extends Schema.Codec<unknown, unknown>, A>(result: S, call: () => Promise<A>) =>
  standalone.pipe(
    Effect.andThen(Effect.tryPromise({ try: call, catch: () => Unavailable.make({}) })),
    Effect.flatMap(Schema.decodeUnknownEffect(result)),
    Effect.mapError(() => Unavailable.make({})),
  );

const encode = (record: Record) =>
  Schema.encodeEffect(Payload)(record).pipe(Effect.mapError(() => Unavailable.make({})));

/** Each write awaits one independent Convex mutation. No adapter retry, credential
 * issuance, or callback is inside the mutation; an unknown result stays unavailable.
 */
const layer = Layer.effect(
  Persistence,
  Effect.gen(function* () {
    const ctx = yield* ActionContext;
    const functions = yield* Functions;

    return Persistence.of({
      get: Effect.fnUntraced(function* (namespace, grantId) {
        const payload = yield* invoke(Schema.NullOr(Schema.String), () =>
          ctx.runQuery(functions.get, { namespace, grantId }),
        );

        return payload === null
          ? undefined
          : yield* Schema.decodeUnknownEffect(Payload)(payload).pipe(
              Effect.mapError(() => Unavailable.make({})),
            );
      }),
      insert: Effect.fnUntraced(function* (namespace, grantId, record) {
        const payload = yield* encode(record);

        return yield* invoke(Schema.Boolean, () =>
          ctx.runMutation(functions.insert, { namespace, grantId, payload }),
        );
      }),
      compareAndSet: Effect.fnUntraced(function* (namespace, grantId, version, record) {
        const payload = yield* encode(record);

        return yield* invoke(Schema.Boolean, () =>
          ctx.runMutation(functions.compareAndSet, { namespace, grantId, version, payload }),
        );
      }),
      revoke: Effect.fnUntraced(function* (namespace, grantId) {
        yield* invoke(Schema.Null, () => ctx.runMutation(functions.revoke, { namespace, grantId }));
      }),
    });
  }),
);

export const OAuthServerPersistence = { layer };
