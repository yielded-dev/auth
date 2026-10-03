import {
  defineTable,
  internalMutationGeneric,
  internalQueryGeneric,
  type DataModelFromSchemaDefinition,
  type GenericDatabaseReader,
  type QueryBuilder,
  type MutationBuilder,
  type SchemaDefinition,
} from "convex/server";
import { v } from "convex/values";
import { Context, DateTime, Effect, Schema } from "effect";

import { Commit, Read, PersistenceUnavailable, type Selection } from "./document-models";

export const documentTables = {
  yieldedAuthDocuments: defineTable({
    namespace: v.string(),
    partition: v.string(),
    key: v.string(),
    revision: v.number(),
    payload: v.string(),
  }).index("by_key", ["namespace", "partition", "key"]),
};

type DataModel = DataModelFromSchemaDefinition<SchemaDefinition<typeof documentTables, true>>;
const query: QueryBuilder<DataModel, "internal"> = internalQueryGeneric;
const mutation: MutationBuilder<DataModel, "internal"> = internalMutationGeneric;

class Reader extends Context.Service<Reader, GenericDatabaseReader<DataModel>>()(
  "effect-auth/convex/DocumentReader",
) {}

const call = <A>(run: () => Promise<A>) =>
  Effect.tryPromise({ try: run, catch: () => PersistenceUnavailable.make({}) });

const select = Effect.fnUntraced(function* (namespace: string, selection: Selection) {
  const db = yield* Reader;

  const rows = yield* call(() => {
    if (selection._tag === "Point")
      return db
        .query("yieldedAuthDocuments")
        .withIndex("by_key", (q) =>
          q
            .eq("namespace", namespace)
            .eq("partition", selection.partition)
            .eq("key", selection.key),
        )
        .take(2);

    return db
      .query("yieldedAuthDocuments")
      .withIndex("by_key", (q) => {
        const range = q.eq("namespace", namespace).eq("partition", selection.partition);

        return selection.after === null ? range : range.gt("key", selection.after);
      })
      .take(selection.limit);
  });

  if (selection._tag === "Point" && rows.length > 1) return yield* PersistenceUnavailable.make({});

  return rows;
});

/** Reads are bounded indexed ranges; the commit repeats the same range, including empty reads. */
export const readDocuments = query({
  args: { command: v.string() },
  handler: (ctx, args) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const input = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Read))(args.command);
        const rows = yield* select(input.namespace, input.selection);

        return {
          now: DateTime.toEpochMillis(yield* DateTime.now),
          rows: rows.map((row) => ({
            id: row._id,
            key: row.key,
            revision: row.revision,
            payload: row.payload,
          })),
        };
      }).pipe(
        Effect.provideService(Reader, ctx.db),
        Effect.mapError(() => PersistenceUnavailable.make({})),
      ),
    ),
});

/** One native transaction validates all reads, time bounds and writes. A failed guard writes nothing. */
export const commitDocuments = mutation({
  args: { command: v.string() },
  handler: (ctx, args) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const input = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Commit))(
          args.command,
        );

        const now = DateTime.toEpochMillis(yield* DateTime.now);

        if (now < input.startedAt || now >= input.before) return "Expired" as const;
        for (const observation of input.observations) {
          const actual = yield* select(input.namespace, observation.selection);

          if (
            actual.length !== observation.rows.length ||
            actual.some((row, i) => {
              const expected = observation.rows[i];

              return (
                expected === undefined ||
                row._id !== expected.id ||
                row.key !== expected.key ||
                row.revision !== expected.revision ||
                row.payload !== expected.payload
              );
            })
          )
            return "Conflict" as const;
        }
        const keys = new Set<string>();

        for (const write of input.writes) {
          const identity = JSON.stringify([write.partition, write.key]);

          if (
            keys.has(identity) ||
            !input.observations.some(
              (observation) =>
                observation.selection._tag === "Point" &&
                observation.selection.partition === write.partition &&
                observation.selection.key === write.key,
            )
          )
            return yield* PersistenceUnavailable.make({});
          keys.add(identity);

          const rows = yield* select(input.namespace, {
            _tag: "Point",
            partition: write.partition,
            key: write.key,
          });

          const current = rows[0];
          const payload = write.payload;

          if (payload === null) {
            if (current !== undefined)
              yield* call(() => ctx.db.delete("yieldedAuthDocuments", current._id));
          } else if (current === undefined) {
            yield* call(() =>
              ctx.db.insert("yieldedAuthDocuments", {
                namespace: input.namespace,
                partition: write.partition,
                key: write.key,
                revision: 0,
                payload,
              }),
            );
          } else {
            if (!Number.isSafeInteger(current.revision + 1))
              return yield* PersistenceUnavailable.make({});
            yield* call(() =>
              ctx.db.patch("yieldedAuthDocuments", current._id, {
                revision: current.revision + 1,
                payload,
              }),
            );
          }
        }

        return "Committed" as const;
      }).pipe(
        Effect.provideService(Reader, ctx.db),
        Effect.mapError(() => PersistenceUnavailable.make({})),
      ),
    ),
});
