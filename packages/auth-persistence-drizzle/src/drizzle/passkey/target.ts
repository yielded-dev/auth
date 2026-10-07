import {
  captureSqlBatchStatements,
  makeBatchPasskeyServices,
  makeNativePasskeyCeremonyServices,
  makeNativePasskeyCredentialServices,
  makeNativePasskeyServices,
  makeSqlCommitExecutor,
  requireStandalone,
  SqlBatchCommit,
  SqlNativeCommit,
  type NativeSqlTables,
  type NativePasskeyCeremonyMapping,
  type PasskeyNativeMapping,
  type PasskeyNativeRead,
} from "@yielded/auth-persistence/Adapter";
import { hasCommitScope, LifecycleHooks } from "@yielded/auth/Hooks";
import { PasskeyConfigurationError, PasskeyUnavailable } from "@yielded/auth/Passkey";
import { type Crypto, Effect } from "effect";
import { SqlClient } from "effect/sql";

import { D1BatchStatements } from "../D1BatchStatements";
import type { PersistenceMappingError } from "../model";
import { NativeDatabase, type NativeDatabaseHandle } from "../native-database";
import { makeDrizzleSqlTables } from "../native-sql-table";
import type { PasskeyPersistenceServices, PasskeyMappingSource } from "../passkey-model";
import { validateDrizzleStorage } from "../storage-validation";
import {
  sqlClientTransactionStandaloneGuard,
  type TransactionTargetConfiguration,
} from "../transaction-execution";
import {
  makeDrizzleTransactionHandle,
  type DrizzleTransactionConstructor,
  type DrizzleTransactionFactory,
} from "../transaction-handle";
import { makeMysqlTransactionHandle, mysqlNativeCommit } from "../transaction-mysql";
import type { TransactionNativeDatabase } from "../transaction-owner";

export type PasskeyTargetConfiguration = TransactionTargetConfiguration<PasskeyUnavailable> & {
  readonly transactionConstructor?: DrizzleTransactionConstructor;
  readonly transactionFactory?: DrizzleTransactionFactory;
};

export type PasskeyCoordinatorError<E> =
  | E
  | PasskeyUnavailable
  | PasskeyConfigurationError
  | PersistenceMappingError;

const unavailable = () => PasskeyUnavailable.make({});

export const sqlClientPasskeyStandaloneGuard = (
  marker: Parameters<typeof sqlClientTransactionStandaloneGuard>[1],
) => sqlClientTransactionStandaloneGuard(unavailable, marker);

const withPhysicalOwner = <A, E, R>(
  effect: Effect.Effect<A, E, R>,
  database: Pick<NativeDatabaseHandle, "$client">,
  configuration: PasskeyTargetConfiguration,
) =>
  configuration.dialect === "mysql"
    ? effect.pipe(Effect.provideService(SqlNativeCommit, mysqlNativeCommit(database.$client)))
    : effect;

const emptyHooks: LifecycleHooks["Service"] = {
  before: () => Effect.void,
  after: () => Effect.succeed([]),
};

// Mapped table/SQL generics end here. Persisted values are decoded by shared schemas.
export const capturePasskeyMapping = <M, R>(
  source: PasskeyMappingSource<M, R>,
  configuration: PasskeyTargetConfiguration,
) =>
  Effect.flatMap(Effect.isEffect(source) ? source : Effect.succeed(source), (mapping) =>
    validateDrizzleStorage(mapping).pipe(
      Effect.andThen(
        Effect.try({
          try: () => {
            if (
              configuration.mode === "batch" &&
              !(
                typeof mapping === "object" &&
                mapping !== null &&
                "d1" in mapping &&
                typeof mapping.d1 === "object" &&
                mapping.d1 !== null &&
                "primary" in mapping.d1 &&
                mapping.d1.primary === true
              )
            )
              throw PasskeyConfigurationError.make({});

            return mapping;
          },
          catch: () => PasskeyConfigurationError.make({}),
        }),
      ),
    ),
  );

type NativePasskeyServices = Effect.Success<ReturnType<typeof makeNativePasskeyServices>>;

interface PasskeyMapped<M> {
  readonly mapping: M;
  readonly database: TransactionNativeDatabase;
  readonly tables: NativeSqlTables;
  readonly batch: SqlBatchCommit["Service"];
  readonly provide: <A, E, R>(
    effect: Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E, Exclude<Exclude<R, SqlClient.SqlClient>, SqlBatchCommit>>;
  readonly base: () => Effect.Effect<NativePasskeyServices, never, Crypto.Crypto | LifecycleHooks>;
}

export const makePasskeyMapped = Effect.fnUntraced(function* <M, R>(
  source: PasskeyMappingSource<M, R>,
  configuration: PasskeyTargetConfiguration,
): Effect.fn.Return<
  PasskeyMapped<M>,
  PasskeyConfigurationError | PersistenceMappingError,
  R | NativeDatabase
> {
  const mapping = yield* capturePasskeyMapping(source, configuration);
  const database = yield* NativeDatabase;
  const tables = makeDrizzleSqlTables(database.$client, database);

  const batch = {
    client: database.$client,
    execute: (statements: Parameters<SqlBatchCommit["Service"]["execute"]>[0]) =>
      database.$client.batch(statements).pipe(Effect.asVoid),
  };

  const native = mapping as unknown as PasskeyNativeMapping;

  const provide = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    withPhysicalOwner(
      effect.pipe(
        Effect.provideService(SqlClient.SqlClient, database.$client),
        Effect.provideService(SqlBatchCommit, batch),
      ),
      database,
      configuration,
    );

  return {
    mapping,
    database,
    tables,
    batch,
    provide,
    base: () =>
      provide(
        configuration.mode === "batch"
          ? makeBatchPasskeyServices(tables, native)
          : makeNativePasskeyServices(tables, native),
      ),
  };
});

export const makeTargetPasskeyCredentials = <M, R>(
  source: PasskeyMappingSource<M, R>,
  configuration: PasskeyTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* makePasskeyMapped(source, configuration);

    return yield* target
      .provide(
        makeNativePasskeyCredentialServices(
          target.tables,
          target.mapping as unknown as PasskeyNativeRead,
        ),
      )
      .pipe(Effect.provideService(LifecycleHooks, emptyHooks));
  }).pipe(Effect.catchDefect(() => Effect.fail(PasskeyConfigurationError.make({}))));

export const makeTargetPasskeyPersistence = <M, R>(
  source: PasskeyMappingSource<M, R>,
  configuration: PasskeyTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* makePasskeyMapped(source, configuration);

    const base = yield* target.base();

    return { passkeyPersistence: base.passkeyPersistence } satisfies PasskeyPersistenceServices;
  });

export const makeTargetPasskeyRegistration = <M, R>(
  source: PasskeyMappingSource<M, R>,
  configuration: PasskeyTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* makePasskeyMapped(source, configuration);

    return yield* target.provide(
      makeNativePasskeyCeremonyServices(
        target.tables,
        target.mapping as unknown as NativePasskeyCeremonyMapping,
        configuration.mode === "batch" ? target.batch : undefined,
      ),
    );
  });

export const coordinatePasskeyOwner = <S, Transaction, A, E, R, ESetup, RSetup>(
  database: NativeDatabaseHandle,
  configuration: PasskeyTargetConfiguration,
  make: Effect.Effect<S, ESetup, RSetup>,
  body: (transaction: Transaction, services: S) => Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  E | PasskeyUnavailable,
  Exclude<R, D1BatchStatements> | RSetup | LifecycleHooks
> =>
  withPhysicalOwner(
    Effect.gen(function* () {
      if (yield* hasCommitScope) return yield* unavailable();
      yield* requireStandalone(unavailable, database.$client.transactionService);
      const executor = yield* makeSqlCommitExecutor(unavailable);

      const work = Effect.gen(function* () {
        const services = yield* make.pipe(Effect.mapError(unavailable));

        const transaction =
          configuration.mode === "batch"
            ? undefined
            : configuration.dialect === "mysql"
              ? yield* makeMysqlTransactionHandle(database)
              : (configuration.transactionFactory?.(database) ??
                makeDrizzleTransactionHandle(database, configuration.transactionConstructor));

        const collector = yield* captureSqlBatchStatements;

        return yield* body(transaction as Transaction, services).pipe(
          Effect.provideService(D1BatchStatements, {
            append: (statement) => collector.append(statement).pipe(Effect.orDie),
          }),
        );
      });

      return yield* configuration.mode === "batch"
        ? executor.coordinateBatch(work)
        : executor.coordinate(work);
    }).pipe(
      Effect.provideService(SqlClient.SqlClient, database.$client),
      Effect.provideService(SqlBatchCommit, {
        client: database.$client,
        execute: (statements) => database.$client.batch(statements).pipe(Effect.asVoid),
      }),
    ),
    database,
    configuration,
  );

export const coordinateTargetPasskey = <M, RSetup, Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  source: PasskeyMappingSource<M, RSetup>,
  configuration: PasskeyTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetPasskeyPersistence>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinatePasskeyOwner(
    database,
    configuration,
    makeTargetPasskeyPersistence(source, configuration),
    body,
  );

export const coordinateTargetPasskeyRegistration = <M, RSetup, Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  source: PasskeyMappingSource<M, RSetup>,
  configuration: PasskeyTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetPasskeyRegistration>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinatePasskeyOwner(
    database,
    configuration,
    makeTargetPasskeyRegistration(source, configuration),
    body,
  );
