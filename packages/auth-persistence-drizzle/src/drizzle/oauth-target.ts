import {
  captureOAuthMapping,
  captureSqlBatchStatements,
  makeNativeOAuthSignInServices,
  makeNativeOAuthAccountsServices,
  makeNativeOAuthRegistrationIntentServices,
  makeNativeOAuthRegistrationServices,
  makeNativeOAuthConnectedServices,
  makeNativeOAuthRevocationServices,
  makeSqlCommitExecutor,
  requireStandalone,
  SqlBatchCommit,
  SqlNativeCommit,
  type OAuthNativeReadMapping,
  type OAuthNativeAccountsMapping,
  type OAuthNativeRegistrationIntentMapping,
  type OAuthNativeRegistrationMapping,
  type OAuthNativeConnectedMapping,
  type OAuthNativeRevocationMapping,
} from "@yielded/auth-persistence/Adapter";
import { hasCommitScope, type LifecycleHooks } from "@yielded/auth/Hooks";
import { OAuthUnavailable } from "@yielded/auth/OAuth";
import { Effect } from "effect";
import { SqlClient } from "effect/sql";

import { D1BatchStatements } from "./D1BatchStatements";
import { NativeDatabase, type NativeDatabaseHandle } from "./native-database";
import { makeDrizzleSqlTables } from "./native-sql-table";
import { validateDrizzleStorage } from "./storage-validation";
import { type TransactionTargetConfiguration } from "./transaction-execution";
import {
  makeDrizzleTransactionHandle,
  type DrizzleTransactionConstructor,
  type DrizzleTransactionFactory,
} from "./transaction-handle";
import { makeMysqlTransactionHandle, mysqlNativeCommit } from "./transaction-mysql";

export {
  oauthAccountsPersistenceLayer,
  oauthSignInPersistenceLayer,
  oauthRegistrationIntentsLayer,
  oauthRegistrationAuthorityLayer,
  oauthConnectedPersistenceLayer,
  oauthConnectedRevocationsLayer,
} from "@yielded/auth-persistence/Adapter";

export type OAuthTargetConfiguration = TransactionTargetConfiguration<OAuthUnavailable> & {
  readonly transactionConstructor?: DrizzleTransactionConstructor;
  readonly transactionFactory?: DrizzleTransactionFactory;
};

export type OAuthCoordinatorError<E> = E | OAuthUnavailable;
const unavailable = () => OAuthUnavailable.make({});

export const sqlClientOAuthStandaloneGuard = (marker: Parameters<typeof requireStandalone>[1]) =>
  requireStandalone(unavailable, marker);

const physical = <A, E, R>(
  work: Effect.Effect<A, E, R>,
  database: Pick<NativeDatabaseHandle, "$client">,
  configuration: OAuthTargetConfiguration,
) =>
  configuration.dialect === "mysql"
    ? Effect.provideService(work, SqlNativeCommit, mysqlNativeCommit(database.$client))
    : work;

const mapped = Effect.fnUntraced(function* (
  original: unknown,
  configuration: OAuthTargetConfiguration,
) {
  const database = yield* NativeDatabase;
  const mapping = captureOAuthMapping(original);

  yield* validateDrizzleStorage(mapping).pipe(Effect.mapError(unavailable));
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
    return yield* unavailable();

  const batch: SqlBatchCommit["Service"] = {
    client: database.$client,
    execute: (statements) => database.$client.batch(statements).pipe(Effect.asVoid),
  };

  return {
    mapping,
    tables: makeDrizzleSqlTables(database.$client, database),
    batch: configuration.mode === "batch" ? batch : undefined,
    provide: <A, E, R>(work: Effect.Effect<A, E, R>) =>
      physical(
        work.pipe(
          Effect.provideService(SqlClient.SqlClient, database.$client),
          Effect.provideService(SqlBatchCommit, batch),
        ),
        database,
        configuration,
      ),
  };
});

export const makeTargetOAuthSignInServices = (
  source: unknown,
  configuration: OAuthTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* mapped(source, configuration);

    return yield* target.provide(
      makeNativeOAuthSignInServices(
        target.tables,
        target.mapping as OAuthNativeReadMapping,
        target.batch,
      ),
    );
  });

export const makeTargetOAuthAccountsServices = (
  source: unknown,
  configuration: OAuthTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* mapped(source, configuration);

    return yield* target.provide(
      makeNativeOAuthAccountsServices(
        target.tables,
        target.mapping as OAuthNativeAccountsMapping,
        target.batch,
      ),
    );
  });

export const makeTargetOAuthRegistrationIntentServices = (
  source: unknown,
  configuration: OAuthTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* mapped(source, configuration);

    return yield* target.provide(
      makeNativeOAuthRegistrationIntentServices(
        target.tables,
        target.mapping as OAuthNativeRegistrationIntentMapping,
        target.batch,
      ),
    );
  });

export const makeTargetOAuthConnectedServices = (
  source: unknown,
  configuration: OAuthTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* mapped(source, configuration);

    return yield* target.provide(
      makeNativeOAuthConnectedServices(
        target.tables,
        target.mapping as OAuthNativeConnectedMapping,
        target.batch,
      ),
    );
  });

export const makeTargetOAuthConnectedRevocationServices = (
  source: unknown,
  configuration: OAuthTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* mapped(source, configuration);

    return yield* target.provide(
      makeNativeOAuthRevocationServices(
        target.tables,
        target.mapping as OAuthNativeRevocationMapping,
        target.batch,
      ),
    );
  });

export const makeTargetOAuthRegistrationServices = <Registration>(
  source: unknown,
  configuration: OAuthTargetConfiguration,
) =>
  Effect.gen(function* () {
    const target = yield* mapped(source, configuration);

    return yield* target.provide(
      makeNativeOAuthRegistrationServices(
        target.tables,
        target.mapping as OAuthNativeRegistrationMapping<Registration>,
        target.batch,
      ),
    );
  });

const coordinateOwner = <Services, Transaction, A, E, R, ES, RS>(
  database: NativeDatabaseHandle,
  configuration: OAuthTargetConfiguration,
  make: Effect.Effect<Services, ES, RS>,
  body: (transaction: Transaction, services: Services) => Effect.Effect<A, E, R>,
): Effect.Effect<A, E | OAuthUnavailable, Exclude<R, D1BatchStatements> | RS | LifecycleHooks> =>
  physical(
    Effect.gen(function* () {
      if (yield* hasCommitScope) return yield* unavailable();
      if (configuration.mode !== "batch")
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

export const coordinateTargetOAuthSignIn = <Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  mapping: unknown,
  configuration: OAuthTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetOAuthSignInServices>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateOwner(
    database,
    configuration,
    makeTargetOAuthSignInServices(mapping, configuration),
    body,
  );

export const coordinateTargetOAuthAccounts = <Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  mapping: unknown,
  configuration: OAuthTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetOAuthAccountsServices>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateOwner(
    database,
    configuration,
    makeTargetOAuthAccountsServices(mapping, configuration),
    body,
  );

export const coordinateTargetOAuthRegistrationIntents = <Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  mapping: unknown,
  configuration: OAuthTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetOAuthRegistrationIntentServices>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateOwner(
    database,
    configuration,
    makeTargetOAuthRegistrationIntentServices(mapping, configuration),
    body,
  );

export const coordinateTargetOAuthConnected = <Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  mapping: unknown,
  configuration: OAuthTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetOAuthConnectedServices>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateOwner(
    database,
    configuration,
    makeTargetOAuthConnectedServices(mapping, configuration),
    body,
  );

export const coordinateTargetOAuthConnectedRevocations = <Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  mapping: unknown,
  configuration: OAuthTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetOAuthConnectedRevocationServices>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateOwner(
    database,
    configuration,
    makeTargetOAuthConnectedRevocationServices(mapping, configuration),
    body,
  );

export const coordinateTargetOAuthRegistration = <Registration, Transaction, A, E, R>(
  database: NativeDatabaseHandle,
  mapping: unknown,
  configuration: OAuthTargetConfiguration,
  body: (
    transaction: Transaction,
    services: Effect.Success<ReturnType<typeof makeTargetOAuthRegistrationServices<Registration>>>,
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateOwner(
    database,
    configuration,
    makeTargetOAuthRegistrationServices<Registration>(mapping, configuration),
    body,
  );
