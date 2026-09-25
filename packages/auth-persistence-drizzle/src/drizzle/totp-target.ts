import { randomId } from "@yielded/auth-crypto";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import {
  TotpConfigurationError,
  type TotpUnavailable,
  TotpMutation,
  TotpPolicy,
  TotpPersistence,
} from "@yielded/auth/Totp";
import type { Table } from "drizzle-orm";
/* oxlint-disable no-explicit-any -- shared native implementation; driver entrypoints retain exact database and table types. */
import { Context, Effect, Schema } from "effect";
import type { Statement } from "effect/unstable/sql/Statement";

import type { PersistenceMappingError } from "./model";
import type { SuppliedService } from "./SuppliedService";
import {
  type TotpMapping,
  type TotpMappingSource,
  type TotpPersistenceServices,
  requiredTotpConstraints,
} from "./totp-model";
import {
  captureTotp,
  CurrentTotpTransaction,
  invariant,
  mutateTotp,
  unavailable,
} from "./totp-state";
import {
  coordinateTransactionOwner,
  makeTransactionExecution,
  sqlClientTransactionStandaloneGuard,
  type TransactionExecution,
  type TransactionTargetConfiguration,
  type TransactionCoordinatorError,
} from "./transaction-execution";
import type { TransactionNativeDatabase } from "./transaction-owner";
export type TotpTargetConfiguration = TransactionTargetConfiguration<TotpUnavailable>;

export type TotpCoordinatorError<E> =
  | TransactionCoordinatorError<E, TotpUnavailable>
  | TotpConfigurationError
  | PersistenceMappingError;

export const sqlClientTotpStandaloneGuard = (
  database: Parameters<typeof sqlClientTransactionStandaloneGuard>[1],
) => sqlClientTransactionStandaloneGuard(unavailable, database);

const validateMapping = <M>(original: M, configuration: TotpTargetConfiguration): M => {
  const mapping = original as any;

  invariant(mapping.moduleId.length > 0);
  Schema.decodeSync(TotpPolicy)(mapping.policy);
  for (const [key, value] of Object.entries(requiredTotpConstraints))
    invariant(mapping.constraints?.[key] === value);
  if (configuration.mode === "batch") invariant(mapping.d1?.primary === true);

  return Object.freeze({
    ...mapping,
    policy: Object.freeze({ ...mapping.policy }),
    subject: Object.freeze({ ...mapping.subject }),
    factor: Object.freeze({ ...mapping.factor }),
    credential: Object.freeze({ ...mapping.credential }),
    subjectIds: Object.freeze({ ...mapping.subjectIds }),
  });
};

const services = (
  mapping: any,
  execution: TransactionExecution<TotpUnavailable, CurrentTotpTransaction>,
  hooks: LifecycleHooks["Service"],
): TotpPersistenceServices => ({
  totpPersistence: TotpPersistence.of({
    snapshot: Effect.fn("TotpNative.snapshot")(
      function* (input) {
        const captured = { ...input };

        invariant(captured.moduleId === mapping.moduleId);
        yield* execution.admit;

        return yield* execution
          .run(
            Effect.map(captureTotp(mapping, captured.subjectId), (value) => value?.snapshot),
            false,
          )
          .pipe(Effect.provideService(LifecycleHooks, hooks));
      },
      Effect.catchDefect(() => Effect.fail(unavailable())),
    ),
    mutate: (original, prepare) =>
      Effect.suspend(() => {
        // Detach caller-owned payloads before any driver or hook can suspend.
        const codec = Schema.toCodecIso(TotpMutation);
        const input = Schema.decodeSync(codec)(Schema.encodeSync(codec)(original));

        return execution.admit.pipe(
          Effect.andThen(
            execution.run(
              Effect.gen(function* () {
                const decision = yield* mutateTotp(mapping, input),
                  owner = yield* CurrentTotpTransaction;

                owner.guards.push(owner.journal.prepare(undefined));
                const receipt = prepare(decision, owner.journal);

                invariant(receipt?._tag === "PreparedCommit" && Effect.isEffect(receipt.read));
                owner.guards.push(receipt as any);

                return receipt;
              }),
            ),
          ),
          Effect.provideService(LifecycleHooks, hooks),
        );
      }).pipe(Effect.catchDefect(() => Effect.fail(unavailable()))),
  }),
});

export const makeTargetTotpPersistence = <
  S extends Table,
  F extends Table,
  C extends Table,
  N,
  RSetup = never,
>(
  database: TransactionNativeDatabase,
  source: TotpMappingSource<TotpMapping<S, F, C, N>, RSetup>,
  configuration: TotpTargetConfiguration,
) =>
  Effect.gen(function* () {
    const hooks = yield* LifecycleHooks;
    const original = yield* Effect.isEffect(source) ? source : Effect.succeed(source);

    const mapping = yield* Effect.try({
      try: () => validateMapping(original, configuration),
      catch: () => TotpConfigurationError.make({}),
    });

    const execution = makeTransactionExecution(
      CurrentTotpTransaction,
      database,
      configuration,
      unavailable,
      randomId,
    );

    return services(mapping, execution, hooks);
  });

export const coordinateTargetTotp = <M, A, E, R, RSetup = never>(
  database: TransactionNativeDatabase,
  source: TotpMappingSource<M, RSetup>,
  configuration: TotpTargetConfiguration,
  body: (
    transaction: any,
    services: TotpPersistenceServices,
    append: (statement: Statement<any>) => void,
  ) => Effect.Effect<A, E, R>,
): Effect.Effect<A, TotpCoordinatorError<E>, R | RSetup | LifecycleHooks> =>
  Effect.gen(function* () {
    const hooks = yield* LifecycleHooks;
    const original = yield* Effect.isEffect(source) ? source : Effect.succeed(source);

    const mapping = yield* Effect.try({
      try: () => validateMapping(original, configuration),
      catch: () => TotpConfigurationError.make({}),
    });

    return yield* coordinateTransactionOwner(
      database,
      CurrentTotpTransaction,
      configuration,
      Effect.void,
      unavailable,
      randomId,
      (execution) => services(mapping, execution, hooks),
      body,
    );
  });

type TransactionOf<D> = D extends { readonly transaction: (...args: any[]) => any }
  ? Parameters<Parameters<D["transaction"]>[0]>[0]
  : never;

/** Concrete driver wrappers select transaction mode; cryptography always precedes these owners. */
export const makeTotpTarget = <
  D extends { readonly transaction: any },
  T extends Table,
  Extra = unknown,
  Synchronous extends boolean = false,
>(
  configuration: TotpTargetConfiguration,
) => {
  function coordinateTotpPersistence<
    Database extends D,
    S extends T,
    F extends T,
    C extends T,
    N,
    A,
    E,
    R,
    RSetup = never,
    DatabaseError = never,
    DatabaseRequirements = never,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: TotpMappingSource<TotpMapping<S, F, C, N> & Extra, RSetup>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TotpPersistence> : R>,
  ): Effect.Effect<
    A,
    TotpCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TotpPersistence>)
    | LifecycleHooks
    | RSetup
    | DatabaseRequirements
  >;
  function coordinateTotpPersistence<
    Database extends D,
    S extends T,
    F extends T,
    C extends T,
    N,
    A,
    E,
    R,
    TxId,
    TxShape,
    RSetup = never,
    DatabaseError = never,
    DatabaseRequirements = never,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: TotpMappingSource<TotpMapping<S, F, C, N> & Extra, RSetup>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TotpPersistence | TxId> : R>,
  ): Effect.Effect<
    A,
    TotpCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TotpPersistence | TxId>)
    | LifecycleHooks
    | RSetup
    | DatabaseRequirements
  >;
  function coordinateTotpPersistence<
    Database extends D,
    S extends T,
    F extends T,
    C extends T,
    N,
    A,
    E,
    R,
    TxId,
    TxShape,
    RSetup = never,
    DatabaseError = never,
    DatabaseRequirements = never,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: TotpMappingSource<TotpMapping<S, F, C, N> & Extra, RSetup>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    TotpCoordinatorError<E> | DatabaseError,
    Exclude<R, TotpPersistence> | LifecycleHooks | RSetup | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetTotp(
        database as any,
        options.mapping,
        configuration,
        (transaction: TransactionOf<Database>, services) => {
          const provided = Context.make(TotpPersistence, services.totpPersistence);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }

  return {
    makeTotpPersistenceServices: <
      Database extends D,
      S extends T,
      F extends T,
      C extends T,
      N,
      RSetup = never,
    >(
      database: Database,
      mapping: TotpMappingSource<TotpMapping<S, F, C, N> & Extra, RSetup>,
    ) => makeTargetTotpPersistence(database as any, mapping, configuration),
    coordinateTotpPersistence,
  };
};
