import type { LifecycleHooks } from "@yielded/auth/Hooks";
import { PasskeyManagementPersistence, PasskeyPersistence } from "@yielded/auth/Passkey";
import type { Table } from "drizzle-orm";
import { Context, Effect } from "effect";

import type { PasskeyMappingSource } from "./passkey-model";
import type { PasskeyCoordinatorError, PasskeyTargetConfiguration } from "./passkey-target";
import type {
  PasskeyManagementMapping,
  PasskeyRegistrationMapping,
  PasskeyRegistrationWriter,
} from "./passkey-write-model";
import {
  coordinateTargetPasskeyManagement,
  coordinateTargetPasskeyRegistrationWriter,
  makeTargetPasskeyManagement,
  makeTargetPasskeyRegistrationWriter,
} from "./passkey-write-target";
import type { SuppliedService } from "./SuppliedService";
// oxlint-disable-next-line no-explicit-any -- inspect the installed concrete transaction callback.
type TransactionOf<D> = D extends { readonly transaction: (...args: any[]) => any }
  ? Parameters<Parameters<D["transaction"]>[0]>[0]
  : never;

export const makePasskeyWriteTarget = <
  D,
  T extends Table,
  Extra = unknown,
  Synchronous extends boolean = false,
>(
  configuration: PasskeyTargetConfiguration,
) => {
  function coordinatePasskeyManagement<
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Command extends T,
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
      readonly mapping: PasskeyMappingSource<
        PasskeyManagementMapping<S, C, F, O, H, M, Flow, Admission, Charge, Command, N> & Extra,
        RSetup
      >;
      readonly transaction?: never;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<PasskeyPersistence | PasskeyManagementPersistence> : R
    >,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true
        ? never
        : Exclude<R, PasskeyPersistence | PasskeyManagementPersistence>)
    | LifecycleHooks
    | RSetup
    | DatabaseRequirements
  >;
  function coordinatePasskeyManagement<
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Command extends T,
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
      readonly mapping: PasskeyMappingSource<
        PasskeyManagementMapping<S, C, F, O, H, M, Flow, Admission, Charge, Command, N> & Extra,
        RSetup
      >;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true
        ? NoInfer<PasskeyPersistence | PasskeyManagementPersistence | TxId>
        : R
    >,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true
        ? never
        : Exclude<R, PasskeyPersistence | PasskeyManagementPersistence | TxId>)
    | LifecycleHooks
    | RSetup
    | DatabaseRequirements
  >;
  function coordinatePasskeyManagement<
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Command extends T,
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
      readonly mapping: PasskeyMappingSource<
        PasskeyManagementMapping<S, C, F, O, H, M, Flow, Admission, Charge, Command, N> & Extra,
        RSetup
      >;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | Exclude<R, PasskeyPersistence | PasskeyManagementPersistence>
    | LifecycleHooks
    | RSetup
    | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetPasskeyManagement(
        database,
        options.mapping,
        configuration,
        (transaction: TransactionOf<Database>, services) => {
          const context = Context.make(PasskeyPersistence, services.passkeyPersistence).pipe(
            Context.add(PasskeyManagementPersistence, services.passkeyManagementPersistence),
          );

          const work = Effect.provideContext(body, context);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }

  const makePasskeyManagementServices = <
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Command extends T,
    N,
    RSetup = never,
  >(
    database: Database,
    mapping: PasskeyMappingSource<
      PasskeyManagementMapping<S, C, F, O, H, M, Flow, Admission, Charge, Command, N> & Extra,
      RSetup
    >,
  ) => makeTargetPasskeyManagement(database, mapping, configuration);

  function coordinatePasskeyRegistration<
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Intent extends T,
    N,
    Value,
    A,
    E,
    R,
    AuthorityId,
    RSetup = never,
    DatabaseError = never,
    DatabaseRequirements = never,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: PasskeyMappingSource<
        PasskeyRegistrationMapping<S, C, F, O, H, M, Flow, Admission, Charge, Intent, N, Value> &
          Extra,
        RSetup
      >;
      readonly authority: Context.Key<AuthorityId, PasskeyRegistrationWriter<Value>>;
      readonly transaction?: never;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<PasskeyPersistence | AuthorityId> : R
    >,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasskeyPersistence | AuthorityId>)
    | LifecycleHooks
    | RSetup
    | DatabaseRequirements
  >;
  function coordinatePasskeyRegistration<
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Intent extends T,
    N,
    Value,
    A,
    E,
    R,
    AuthorityId,
    TxId,
    TxShape,
    RSetup = never,
    DatabaseError = never,
    DatabaseRequirements = never,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: PasskeyMappingSource<
        PasskeyRegistrationMapping<S, C, F, O, H, M, Flow, Admission, Charge, Intent, N, Value> &
          Extra,
        RSetup
      >;
      readonly authority: Context.Key<AuthorityId, PasskeyRegistrationWriter<Value>>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<PasskeyPersistence | AuthorityId | TxId> : R
    >,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasskeyPersistence | AuthorityId | TxId>)
    | LifecycleHooks
    | RSetup
    | DatabaseRequirements
  >;
  function coordinatePasskeyRegistration<
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Intent extends T,
    N,
    Value,
    A,
    E,
    R,
    AuthorityId,
    TxId,
    TxShape,
    RSetup = never,
    DatabaseError = never,
    DatabaseRequirements = never,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: PasskeyMappingSource<
        PasskeyRegistrationMapping<S, C, F, O, H, M, Flow, Admission, Charge, Intent, N, Value> &
          Extra,
        RSetup
      >;
      readonly authority: Context.Key<AuthorityId, PasskeyRegistrationWriter<Value>>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    Exclude<R, PasskeyPersistence | AuthorityId> | LifecycleHooks | RSetup | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetPasskeyRegistrationWriter(
        database,
        options.mapping,
        configuration,
        (
          transaction: TransactionOf<Database>,
          services: import("./passkey-write-model").PasskeyRegistrationServices<Value>,
        ) => {
          const context = Context.make(PasskeyPersistence, services.passkeyPersistence).pipe(
            Context.add(options.authority, services.passkeyRegistrationAuthority),
          );

          const work = Effect.provideContext(body, context);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }

  const makePasskeyRegistrationServices = <
    Database extends D,
    S extends T,
    C extends T,
    F extends T,
    O extends T,
    H extends T,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Intent extends T,
    N,
    Value,
    RSetup = never,
  >(
    database: Database,
    mapping: PasskeyMappingSource<
      PasskeyRegistrationMapping<S, C, F, O, H, M, Flow, Admission, Charge, Intent, N, Value> &
        Extra,
      RSetup
    >,
  ) =>
    makeTargetPasskeyRegistrationWriter<
      PasskeyRegistrationMapping<S, C, F, O, H, M, Flow, Admission, Charge, Intent, N, Value> &
        Extra,
      Value,
      RSetup
    >(database, mapping, configuration);

  return {
    makePasskeyManagementServices,
    makePasskeyRegistrationServices,
    coordinatePasskeyManagement,
    coordinatePasskeyRegistration,
  };
};
