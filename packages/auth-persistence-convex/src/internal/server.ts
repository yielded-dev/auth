import { Unavailable } from "@yielded/auth/OAuthServer";
import {
  type DataModelFromSchemaDefinition,
  defineTable,
  type GenericDatabaseReader,
  internalMutationGeneric,
  internalQueryGeneric,
  type MutationBuilder,
  type QueryBuilder,
  type SchemaDefinition,
} from "convex/server";
import { v } from "convex/values";
import { Context, DateTime, Effect, Schema } from "effect";

import { documentTables } from "./document-server";
import { Cleanup, CompareAndSet, GrantKey, Insert, Payload, StoredGrant } from "./models";

const table = "yieldedAuthOAuthGrants";

/** Merge into the application's Convex schema. The compound index is checked with
 * unique() inside each serializable mutation; it is not itself a unique constraint.
 */
export const tables = {
  ...documentTables,
  [table]: defineTable({
    namespace: v.string(),
    grantId: v.string(),
    payload: v.string(),
    expiresAtMillis: v.number(),
  })
    .index("by_namespace_grant", ["namespace", "grantId"])
    .index("by_expiry", ["expiresAtMillis"]),
};

type DataModel = DataModelFromSchemaDefinition<SchemaDefinition<typeof tables, true>>;
const query: QueryBuilder<DataModel, "internal"> = internalQueryGeneric;
const mutation: MutationBuilder<DataModel, "internal"> = internalMutationGeneric;
const keyArgs = { namespace: v.string(), grantId: v.string() };

class GrantReader extends Context.Service<GrantReader, GenericDatabaseReader<DataModel>>()(
  "effect-auth/convex/GrantReader",
) {}

const database = <A>(run: () => Promise<A>) =>
  Effect.tryPromise({ try: run, catch: () => Unavailable.make({}) });

const decodePayload = Schema.decodeUnknownEffect(Payload);
const encodePayload = Schema.encodeEffect(Payload);

const unavailable = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(Effect.mapError(() => Unavailable.make({})));

const find = Effect.fnUntraced(function* (key: typeof GrantKey.Type) {
  const db = yield* GrantReader;

  const row = yield* database(() =>
    db
      .query(table)
      .withIndex("by_namespace_grant", (q) =>
        q.eq("namespace", key.namespace).eq("grantId", key.grantId),
      )
      .unique(),
  );

  if (row === null) return undefined;
  const stored = yield* Schema.decodeUnknownEffect(StoredGrant)(row);
  const record = yield* decodePayload(stored.payload);

  if (stored.expiresAtMillis !== record.expiresAtMillis) return yield* Unavailable.make({});

  return { id: row._id, record };
}, unavailable);

/** Export these definitions from a Convex module. They are always internal; no
 * browser or unauthenticated HTTP client can call persistence directly.
 */
export const get = query({
  args: keyArgs,
  returns: v.union(v.string(), v.null()),
  handler: (ctx, args) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const key = yield* Schema.decodeUnknownEffect(GrantKey)(args);
        const row = yield* find(key);

        return row === undefined ? null : yield* encodePayload(row.record);
      }).pipe(Effect.provideService(GrantReader, ctx.db), unavailable),
    ),
});

export const insert = mutation({
  args: { ...keyArgs, payload: v.string() },
  returns: v.boolean(),
  handler: (ctx, args) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const input = yield* Schema.decodeUnknownEffect(Insert)(args);
        const record = yield* decodePayload(input.payload);
        const existing = yield* find(input);

        if (existing !== undefined) return false;
        const payload = yield* encodePayload(record);

        yield* database(() =>
          ctx.db.insert(table, {
            namespace: input.namespace,
            grantId: input.grantId,
            payload,
            expiresAtMillis: record.expiresAtMillis,
          }),
        );

        return true;
      }).pipe(Effect.provideService(GrantReader, ctx.db), unavailable),
    ),
});

export const compareAndSet = mutation({
  args: { ...keyArgs, version: v.string(), payload: v.string() },
  returns: v.boolean(),
  handler: (ctx, args) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const input = yield* Schema.decodeUnknownEffect(CompareAndSet)(args);
        const next = yield* decodePayload(input.payload);

        if (next.version === input.version) return yield* Unavailable.make({});
        const current = yield* find(input);

        if (
          current === undefined ||
          current.record.status === "Revoked" ||
          current.record.version !== input.version
        )
          return false;
        const payload = yield* encodePayload(next);

        yield* database(() =>
          ctx.db.patch(table, current.id, {
            payload,
            expiresAtMillis: next.expiresAtMillis,
          }),
        );

        return true;
      }).pipe(Effect.provideService(GrantReader, ctx.db), unavailable),
    ),
});

export const revoke = mutation({
  args: keyArgs,
  returns: v.null(),
  handler: (ctx, args) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const key = yield* Schema.decodeUnknownEffect(GrantKey)(args);
        const current = yield* find(key);

        if (current === undefined || current.record.status === "Revoked") return null;
        const payload = yield* encodePayload({ ...current.record, status: "Revoked" });

        yield* database(() => ctx.db.patch(table, current.id, { payload }));

        return null;
      }).pipe(Effect.provideService(GrantReader, ctx.db), unavailable),
    ),
});

/** Application-scheduled, bounded retention cleanup. Authority time comes from
 * the Convex mutation; a concurrently extended grant is rechecked on retry.
 */
export const cleanup = mutation({
  args: { limit: v.number() },
  returns: v.object({ removed: v.number(), hasMore: v.boolean() }),
  handler: (ctx, args) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const { limit } = yield* Schema.decodeUnknownEffect(Cleanup)(args);
        const now = DateTime.toEpochMillis(yield* DateTime.now);

        const rows = yield* database(() =>
          ctx.db
            .query(table)
            .withIndex("by_expiry", (q) => q.lte("expiresAtMillis", now))
            .take(limit + 1),
        );

        for (const row of rows.slice(0, limit)) {
          const stored = yield* Schema.decodeUnknownEffect(StoredGrant)(row);
          const record = yield* decodePayload(stored.payload);

          if (stored.expiresAtMillis !== record.expiresAtMillis) return yield* Unavailable.make({});
          yield* database(() => ctx.db.delete(table, row._id));
        }

        return { removed: Math.min(rows.length, limit), hasMore: rows.length > limit };
      }).pipe(Effect.provideService(GrantReader, ctx.db), unavailable),
    ),
});
