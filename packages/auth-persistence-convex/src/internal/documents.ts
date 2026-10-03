import {
  coordinateCommit,
  hasCommitScope,
  LifecycleHooks,
  type CommitJournal,
} from "@yielded/auth/Hooks";
import type { FunctionReference } from "convex/server";
import { compareValues } from "convex/values";
import { Clock, Context, Crypto, Effect, Layer, Option, Schema } from "effect";

import {
  Commit,
  CommitResult,
  Read,
  ReadResult,
  PersistenceUnavailable,
  TransactionConflict,
  type Document,
  type Observation,
  type Selection,
  type Write,
} from "./document-models";
import { ActionContext } from "./persistence";

export { PersistenceUnavailable, TransactionConflict } from "./document-models";
export type Codec = Schema.Codec<unknown, unknown, never, never>;

export class DocumentFunctions extends Context.Service<
  DocumentFunctions,
  {
    readonly readDocuments: FunctionReference<
      "query",
      "internal",
      { command: string },
      typeof ReadResult.Type
    >;
    readonly commitDocuments: FunctionReference<
      "mutation",
      "internal",
      { command: string },
      typeof CommitResult.Type
    >;
  }
>()("effect-auth/convex/DocumentFunctions") {}

/** Transaction-bound document access for auth and application provisioning in the same commit. */
export class Transaction extends Context.Service<
  Transaction,
  {
    readonly now: number;
    readonly journal: CommitJournal;
    readonly id: Effect.Effect<string, PersistenceUnavailable>;
    readonly get: <S extends Codec>(
      schema: S,
      partition: string,
      key: string,
    ) => Effect.Effect<S["Type"] | undefined, PersistenceUnavailable>;
    readonly scan: <S extends Codec>(
      schema: S,
      partition: string,
      options?: { readonly after?: string; readonly limit?: number },
    ) => Effect.Effect<
      ReadonlyArray<{ readonly key: string; readonly value: S["Type"] }>,
      PersistenceUnavailable
    >;
    readonly put: <S extends Codec>(
      schema: S,
      partition: string,
      key: string,
      value: S["Type"],
    ) => Effect.Effect<void, PersistenceUnavailable>;
    readonly remove: (
      partition: string,
      key: string,
    ) => Effect.Effect<void, PersistenceUnavailable>;
    /** Register every time-sensitive acceptance predicate before publishing. */
    readonly before: (deadline: number) => Effect.Effect<void, PersistenceUnavailable>;
  }
>()("effect-auth/convex/Transaction") {}

export class DocumentStore extends Context.Service<
  DocumentStore,
  {
    readonly transaction: <A, E, R>(
      body: Effect.Effect<A, E, R>,
    ) => Effect.Effect<
      A,
      E | PersistenceUnavailable | TransactionConflict,
      Exclude<R, Transaction>
    >;
  }
>()("effect-auth/convex/DocumentStore") {
  static readonly layer = (namespace: string) =>
    Layer.effect(
      DocumentStore,
      Effect.gen(function* () {
        const ctx = yield* ActionContext;
        const functions = yield* DocumentFunctions;
        const hooks = yield* LifecycleHooks;
        const crypto = yield* Crypto.Crypto;
        const clock = yield* Clock.Clock;
        const encodeRead = Schema.encodeEffect(Schema.fromJsonString(Read));
        const encodeCommit = Schema.encodeEffect(Schema.fromJsonString(Commit));

        const nativeRead = Effect.fnUntraced(
          function* (selection: Selection, freshClock = false) {
            // Convex may cache query results including Date.now(). A unique argument
            // forces the authority-time sample to execute for this transaction.
            const nonce = freshClock ? yield* crypto.randomUUIDv4 : undefined;

            const command = yield* encodeRead({
              namespace,
              selection,
              ...(nonce === undefined ? {} : { nonce }),
            });

            const result = yield* Effect.tryPromise({
              try: () => ctx.runQuery(functions.readDocuments, { command }),
              catch: () => PersistenceUnavailable.make({}),
            });

            return yield* Schema.decodeUnknownEffect(ReadResult)(result);
          },
          Effect.mapError(() => PersistenceUnavailable.make({})),
        );

        return DocumentStore.of({
          transaction: <A, E, R>(body: Effect.Effect<A, E, R>) =>
            Effect.gen(function* () {
              // Joining is explicit: only this store's own active Transaction may be reused.
              if (
                Option.isSome(yield* Effect.serviceOption(Transaction)) ||
                (yield* hasCommitScope)
              )
                return yield* PersistenceUnavailable.make({});

              const result = yield* coordinateCommit(
                (journal) =>
                  Effect.gen(function* () {
                    const observations: Observation[] = [];
                    const writes = new Map<string, Write>();
                    const pointCache = new Map<string, Document | undefined>();

                    const identity = (partition: string, key: string) =>
                      JSON.stringify([partition, key]);

                    const initial = yield* nativeRead(
                      {
                        _tag: "Point",
                        partition: "clock",
                        key: "sample",
                      },
                      true,
                    );

                    const now = initial.now;
                    // A short planning horizon bounds authority-clock age even for commands without expiry.
                    let before = now + 30_000;
                    let active = true;
                    let poisoned = false;

                    const check = Effect.suspend(() =>
                      active && !poisoned && observations.length < 128 && writes.size < 128
                        ? Effect.void
                        : Effect.fail(PersistenceUnavailable.make({})),
                    );

                    const guarded = <V>(work: Effect.Effect<V, PersistenceUnavailable>) =>
                      check.pipe(
                        Effect.andThen(work),
                        Effect.onError(() =>
                          Effect.sync(() => {
                            poisoned = true;
                          }),
                        ),
                      );

                    const point = Effect.fnUntraced(function* (partition: string, key: string) {
                      const id = identity(partition, key);

                      if (pointCache.has(id)) return pointCache.get(id);
                      const selection: Selection = { _tag: "Point", partition, key };
                      const read = yield* nativeRead(selection);

                      observations.push({ selection, rows: read.rows });
                      const row = read.rows[0];

                      pointCache.set(id, row);

                      return row;
                    });

                    const decode = <S extends Codec>(schema: S, payload: string) =>
                      Schema.decodeUnknownEffect(Schema.fromJsonString(schema))(payload).pipe(
                        Effect.mapError(() => PersistenceUnavailable.make({})),
                      );

                    const transaction = Transaction.of({
                      now,
                      journal,
                      id: guarded(
                        crypto.randomUUIDv4.pipe(
                          Effect.mapError(() => PersistenceUnavailable.make({})),
                        ),
                      ),
                      before: (deadline) =>
                        guarded(
                          Effect.sync(() => {
                            before = Math.min(before, deadline);
                          }).pipe(
                            Effect.andThen(
                              Effect.suspend(() =>
                                Number.isSafeInteger(before) && before > now
                                  ? Effect.void
                                  : Effect.fail(PersistenceUnavailable.make({})),
                              ),
                            ),
                          ),
                        ),
                      get: (schema, partition, key) =>
                        guarded(
                          Effect.gen(function* () {
                            const row = yield* point(partition, key);
                            const staged = writes.get(identity(partition, key));
                            const payload = staged === undefined ? row?.payload : staged.payload;

                            return payload === null || payload === undefined
                              ? undefined
                              : yield* decode(schema, payload);
                          }),
                        ),
                      scan: (schema, partition, options = {}) =>
                        guarded(
                          Effect.gen(function* () {
                            const limit = options.limit ?? 500;
                            let after = options.after ?? null;
                            const persisted = new Map<string, string>();
                            let visible: Array<[string, string]> = [];

                            // A deleted prefix needs refilling before a staged high key can
                            // become a cursor. Observe every native page used to fill it.
                            for (;;) {
                              yield* check;

                              const selection: Selection = {
                                _tag: "Range",
                                partition,
                                after,
                                limit,
                              };

                              const read = yield* nativeRead(selection);

                              observations.push({ selection, rows: read.rows });
                              for (const row of read.rows) {
                                if (persisted.has(row.key))
                                  return yield* PersistenceUnavailable.make({});
                                persisted.set(row.key, row.payload);
                              }
                              const values = new Map(persisted);

                              for (const write of writes.values()) {
                                if (
                                  write.partition !== partition ||
                                  (options.after !== undefined &&
                                    compareValues(write.key, options.after) <= 0)
                                )
                                  continue;
                                if (write.payload === null) values.delete(write.key);
                                else values.set(write.key, write.payload);
                              }
                              visible = [...values].sort(([a], [b]) => compareValues(a, b));
                              if (options.limit === undefined && visible.length >= 500)
                                return yield* PersistenceUnavailable.make({});
                              const last = read.rows.at(-1);
                              const end = visible[limit - 1];

                              if (
                                read.rows.length < limit ||
                                last === undefined ||
                                (end !== undefined && compareValues(end[0], last.key) <= 0)
                              )
                                break;
                              after = last.key;
                            }

                            return yield* Effect.forEach(
                              visible.slice(0, limit),
                              ([key, payload]) =>
                                decode(schema, payload).pipe(
                                  Effect.map((value) => ({ key, value })),
                                ),
                            );
                          }),
                        ),
                      put: (schema, partition, key, value) =>
                        guarded(
                          Effect.gen(function* () {
                            yield* point(partition, key);

                            const payload = yield* Schema.encodeEffect(
                              Schema.fromJsonString(schema),
                            )(value).pipe(Effect.mapError(() => PersistenceUnavailable.make({})));

                            writes.set(identity(partition, key), { partition, key, payload });
                          }),
                        ),
                      remove: (partition, key) =>
                        guarded(
                          Effect.gen(function* () {
                            yield* point(partition, key);
                            writes.set(identity(partition, key), { partition, key, payload: null });
                          }),
                        ),
                    });

                    const value = yield* body.pipe(
                      Effect.provideService(Transaction, transaction),
                      Effect.provideService(Clock.Clock, {
                        currentTimeMillis: Effect.succeed(now),
                        currentTimeMillisUnsafe: () => now,
                        currentTimeNanos: Effect.succeed(BigInt(now) * 1_000_000n),
                        currentTimeNanosUnsafe: () => BigInt(now) * 1_000_000n,
                        monotonicTimeNanos: clock.monotonicTimeNanos,
                        monotonicTimeNanosUnsafe: () => clock.monotonicTimeNanosUnsafe(),
                        sleep: (duration) => clock.sleep(duration),
                      }),
                      Effect.ensuring(
                        Effect.sync(() => {
                          active = false;
                        }),
                      ),
                    );

                    if (poisoned) return yield* PersistenceUnavailable.make({});

                    const command = yield* encodeCommit({
                      namespace,
                      startedAt: now,
                      before,
                      observations,
                      writes: [...writes.values()],
                    }).pipe(Effect.mapError(() => PersistenceUnavailable.make({})));

                    const committed = yield* Effect.tryPromise({
                      try: () => ctx.runMutation(functions.commitDocuments, { command }),
                      catch: () => PersistenceUnavailable.make({}),
                    }).pipe(
                      Effect.flatMap(Schema.decodeUnknownEffect(CommitResult)),
                      Effect.mapError(() => PersistenceUnavailable.make({})),
                    );

                    if (committed === "Conflict") return yield* TransactionConflict.make({});
                    if (committed === "Expired") return yield* PersistenceUnavailable.make({});

                    return value;
                  }),
                { mode: "batch" },
              ).pipe(
                Effect.provideService(LifecycleHooks, hooks),
                Effect.catchTag("HookConfigurationError", () => PersistenceUnavailable.make({})),
              );

              return result.value;
            }),
        });
      }),
    );
}
