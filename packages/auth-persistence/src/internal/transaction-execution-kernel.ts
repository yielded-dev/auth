import {
  coordinateCommit,
  hasCommitScope,
  CurrentCommitJournal,
  type LifecycleHooks,
  type HookConfigurationError,
} from "@yielded/auth/Hooks";
/* oxlint-disable no-explicit-any -- existing storage kernels erase foreign table shapes; domain errors remain typed. */
/* oxlint-disable no-explicit-any -- private execution bridge retains exact public driver wrappers. */
import { Context, Effect, Option } from "effect";
import type * as SqlClient from "effect/unstable/sql/SqlClient";
import type * as SqlError from "effect/unstable/sql/SqlError";
import type { Statement } from "effect/unstable/sql/Statement";

import {
  type TransactionNativeDatabase,
  type TransactionOwner,
  type makeTransactionKernel,
} from "./transaction-kernel";

export interface TransactionTargetConfiguration<Failure> {
  readonly mode: "interactive" | "synchronous" | "batch";
  readonly dialect: "pg" | "mysql" | "sqlite";
  readonly locking: boolean;
  readonly standaloneGuard: (database: any) => Effect.Effect<void, Failure>;
  readonly transaction?: <A, E, R>(
    database: any,
    body: (transaction: any) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | SqlError.SqlError | Failure, R>;
}

export type TransactionCoordinatorError<E, Failure> =
  | E
  | Failure
  | HookConfigurationError
  | SqlError.SqlError;

export interface TransactionBound<Failure> {
  readonly owner: TransactionOwner<Failure>;
  used: boolean;
  poisoned: boolean;
  active: boolean;
  inFlight: number;
}

export interface TransactionExecution<Failure, OwnerId, Requirements = LifecycleHooks> {
  readonly bound: boolean;
  readonly active: () => boolean;
  readonly admit: Effect.Effect<void, Failure>;
  readonly poison: () => void;
  readonly run: <A, E, R>(
    body: Effect.Effect<A, E, R>,
    mutation?: boolean,
  ) => Effect.Effect<A, Failure, Exclude<R, OwnerId | CurrentCommitJournal> | Requirements>;
}

export const makeTransactionExecutionKernel = (
  transactions: Pick<
    ReturnType<typeof makeTransactionKernel>,
    "makeTransactionOwner" | "reportTransactionFailure"
  >,
) => {
  const { makeTransactionOwner, reportTransactionFailure } = transactions;

  const sqlClientTransactionStandaloneGuard = <Failure>(
    unavailable: () => Failure,
    database: {
      readonly $client: Pick<SqlClient.SqlClient, "transactionService">;
    },
  ) =>
    Effect.serviceOption(database.$client.transactionService).pipe(
      Effect.flatMap(
        Option.match({ onNone: () => Effect.void, onSome: () => Effect.fail(unavailable()) }),
      ),
    );

  const makeTransactionExecution = <Failure, OwnerId>(
    ownerTag: Context.Key<OwnerId, TransactionOwner<Failure>>,
    database: TransactionNativeDatabase,
    configuration: TransactionTargetConfiguration<Failure>,
    unavailable: () => Failure,
    nonce: () => string,
    bound?: TransactionBound<Failure>,
  ): TransactionExecution<Failure, OwnerId> => {
    const invariant: (value: unknown) => asserts value = (value) => {
      if (!value) throw unavailable();
    };

    return {
      bound: bound !== undefined,
      active: () => bound === undefined || bound.active,
      admit:
        bound !== undefined
          ? Effect.suspend(() => (bound.active ? Effect.void : Effect.fail(unavailable())))
          : Effect.gen(function* () {
              if (yield* hasCommitScope) return yield* Effect.fail(unavailable());
              yield* configuration.standaloneGuard(database);
            }),
      poison: () => {
        if (bound !== undefined) bound.poisoned = true;
      },
      run: <A, E, R>(
        body: Effect.Effect<A, E, R>,
        mutation = true,
      ): Effect.Effect<A, Failure, Exclude<R, OwnerId | CurrentCommitJournal> | LifecycleHooks> => {
        return Effect.suspend(() => {
          let entered = false;

          const work =
            bound !== undefined
              ? Effect.gen(function* () {
                  if (!bound.active) return yield* Effect.fail(unavailable());
                  entered = true;
                  bound.inFlight++;
                  if (!mutation)
                    return yield* Effect.provideContext(
                      body,
                      Context.make(ownerTag, bound.owner).pipe(
                        Context.add(CurrentCommitJournal, bound.owner.journal),
                      ),
                    );
                  invariant(!bound.used && !bound.poisoned);
                  bound.used = true;

                  const result = yield* coordinateCommit(
                    (journal) =>
                      Effect.gen(function* () {
                        bound.owner.guards.push(journal.prepare(undefined));

                        return yield* Effect.provideContext(
                          body,
                          Context.make(ownerTag, { ...bound.owner, journal }).pipe(
                            Context.add(CurrentCommitJournal, journal),
                          ),
                        );
                      }),
                    { mode: configuration.mode },
                  );

                  return result.value;
                }).pipe(
                  Effect.onExit((exit) =>
                    Effect.sync(() => {
                      if (entered) bound.inFlight--;
                      if (exit._tag === "Failure") bound.poisoned = true;
                    }),
                  ),
                )
              : Effect.gen(function* () {
                  if (yield* hasCommitScope) return yield* Effect.fail(unavailable());
                  yield* configuration.standaloneGuard(database);
                  const marker = nonce();

                  const result = yield* coordinateCommit(
                    (journal) => {
                      const run = (tx: TransactionNativeDatabase) =>
                        Effect.gen(function* () {
                          const owner = makeTransactionOwner(tx, journal, marker, unavailable, {
                            client: database.$client,
                            batch: configuration.mode === "batch",
                            locking: configuration.locking,
                            mysql: configuration.dialect === "mysql",
                            dialect: configuration.dialect,
                          });

                          const value = yield* Effect.provideContext(
                            body,
                            Context.make(ownerTag, owner).pipe(
                              Context.add(CurrentCommitJournal, journal),
                            ),
                          );

                          yield* owner.finish();
                          if (configuration.mode === "batch")
                            yield* tx.$client.batch(owner.statements);

                          return value;
                        });

                      return configuration.mode === "batch"
                        ? run(database)
                        : configuration.transaction !== undefined
                          ? configuration.transaction(database, run)
                          : database.transaction(run);
                    },
                    { mode: configuration.mode },
                  );

                  return result.value;
                });

          return work.pipe(
            (operation) => reportTransactionFailure(operation, unavailable),
            Effect.mapError(unavailable),
            Effect.catchDefect(() => Effect.fail(unavailable())),
          );
        });
      },
    };
  };

  const coordinateTransactionOwner = <
    Failure,
    OwnerId,
    Resources,
    AllocationError,
    Services,
    Transaction,
    A,
    E,
    R,
  >(
    database: TransactionNativeDatabase,
    ownerTag: Context.Key<OwnerId, TransactionOwner<Failure>>,
    configuration: TransactionTargetConfiguration<Failure>,
    allocate: Effect.Effect<Resources, AllocationError>,
    unavailable: () => Failure,
    nonce: () => string,
    services: (execution: TransactionExecution<Failure, OwnerId>, resources: Resources) => Services,
    owner: (
      transaction: Transaction,
      services: Services,
      append: (statement: Statement<any>) => void,
    ) => Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    TransactionCoordinatorError<E, Failure>,
    Exclude<R, CurrentCommitJournal> | LifecycleHooks
  > => {
    return Effect.gen(function* () {
      if (yield* hasCommitScope) return yield* Effect.fail(unavailable());
      yield* configuration.standaloneGuard(database);

      // Allocation is independent of registration data and always precedes the physical owner.
      const resources = yield* allocate.pipe(
        (operation) => reportTransactionFailure(operation, unavailable),
        Effect.mapError(unavailable),
        Effect.catchDefect(() => Effect.fail(unavailable())),
      );

      const marker = nonce();

      const result = yield* coordinateCommit(
        (journal) => {
          const run = (tx: TransactionNativeDatabase) =>
            Effect.gen(function* () {
              const state = makeTransactionOwner(tx, journal, marker, unavailable, {
                client: database.$client,
                batch: configuration.mode === "batch",
                dialect: configuration.dialect,
                mysql: configuration.dialect === "mysql",
                locking: configuration.locking,
              });

              const bound: TransactionBound<Failure> = {
                owner: state,
                used: false,
                poisoned: false,
                active: true,
                inFlight: 0,
              };

              return yield* Effect.gen(function* () {
                const value = yield* owner(
                  tx as Transaction,
                  services(
                    makeTransactionExecution(
                      ownerTag,
                      tx,
                      configuration,
                      unavailable,
                      nonce,
                      bound,
                    ),
                    resources,
                  ),
                  (statement) => {
                    if (!bound.active) throw unavailable();
                    state.statements.push(statement);
                  },
                );

                bound.active = false;
                if (bound.poisoned || bound.inFlight !== 0)
                  return yield* Effect.fail(unavailable());
                yield* state.finish();
                if (configuration.mode === "batch") yield* tx.$client.batch(state.statements);

                return value;
              }).pipe(
                Effect.ensuring(
                  Effect.sync(() => {
                    bound.active = false;
                  }),
                ),
              );
            });

          return configuration.mode === "batch"
            ? run(database)
            : configuration.transaction !== undefined
              ? configuration.transaction(database, run)
              : database.transaction(run);
        },
        { mode: configuration.mode },
      );

      return result.value as A;
    });
  };

  return {
    sqlClientTransactionStandaloneGuard,
    makeTransactionExecution,
    coordinateTransactionOwner,
  };
};
