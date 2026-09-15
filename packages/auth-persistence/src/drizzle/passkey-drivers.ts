import type { LifecycleHooks } from "@yielded/auth/Hooks";
import { PasskeyPersistence } from "@yielded/auth/Passkey";
import type { Table } from "drizzle-orm";
import { Effect, Context } from "effect";

import type {
  PasskeyCredentialMapping,
  PasskeyEnrollmentContextMapping,
  PasskeyMappingSource,
  PasskeyPersistenceMapping,
  PasskeyPersistenceServices,
} from "./passkey-model";
import type {
  PasskeyRegistrationCeremonyMapping,
  PasskeyRegistrationCeremonyServices,
} from "./passkey-registration-ceremony-model";
import {
  type PasskeyCoordinatorError,
  coordinateTargetPasskey,
  coordinateTargetPasskeyRegistration,
  makeTargetPasskeyCredentials,
  makeTargetPasskeyEnrollmentContext,
  makeTargetPasskeyPersistence,
  makeTargetPasskeyRegistration,
  type PasskeyTargetConfiguration,
} from "./passkey-target";
import { makePasskeyWriteTarget } from "./passkey-write-drivers";
import type { SuppliedService } from "./SuppliedService";

// oxlint-disable-next-line no-explicit-any -- inspect only the concrete database's installed generic transaction callback.
type TransactionOf<D> = D extends { readonly transaction: (...args: any[]) => any }
  ? Parameters<Parameters<D["transaction"]>[0]>[0]
  : never;

export const makePasskeyTarget = <
  D,
  T extends Table,
  Extra = unknown,
  Synchronous extends boolean = false,
>(
  configuration: PasskeyTargetConfiguration,
) => {
  function coordinatePasskeyPersistence<
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
        PasskeyPersistenceMapping<
          PasskeyCredentialMapping<S, C, F, O, H, N>,
          M,
          Flow,
          Admission,
          Charge,
          N
        > &
          Extra,
        RSetup
      >;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<PasskeyPersistence> : R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasskeyPersistence>)
    | LifecycleHooks
    | DatabaseRequirements
    | RSetup
  >;
  function coordinatePasskeyPersistence<
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
        PasskeyPersistenceMapping<
          PasskeyCredentialMapping<S, C, F, O, H, N>,
          M,
          Flow,
          Admission,
          Charge,
          N
        > &
          Extra,
        RSetup
      >;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<PasskeyPersistence | TxId> : R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasskeyPersistence | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
    | RSetup
  >;
  function coordinatePasskeyPersistence<
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
        PasskeyPersistenceMapping<
          PasskeyCredentialMapping<S, C, F, O, H, N>,
          M,
          Flow,
          Admission,
          Charge,
          N
        > &
          Extra,
        RSetup
      >;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    Exclude<R, PasskeyPersistence> | LifecycleHooks | DatabaseRequirements | RSetup
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetPasskey(
        database,
        options.mapping,
        configuration,
        (transaction: TransactionOf<Database>, services: PasskeyPersistenceServices) => {
          const provided = Context.make(PasskeyPersistence, services.passkeyPersistence);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinatePasskeyRegistrationCeremony<
    Database extends D,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Intent extends T,
    H extends T,
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
        PasskeyRegistrationCeremonyMapping<M, Flow, Admission, Charge, Intent, H> & Extra,
        RSetup
      >;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<PasskeyPersistence> : R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasskeyPersistence>)
    | LifecycleHooks
    | DatabaseRequirements
    | RSetup
  >;
  function coordinatePasskeyRegistrationCeremony<
    Database extends D,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Intent extends T,
    H extends T,
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
        PasskeyRegistrationCeremonyMapping<M, Flow, Admission, Charge, Intent, H> & Extra,
        RSetup
      >;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<PasskeyPersistence | TxId> : R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasskeyPersistence | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
    | RSetup
  >;
  function coordinatePasskeyRegistrationCeremony<
    Database extends D,
    M extends T,
    Flow extends T,
    Admission extends T,
    Charge extends T,
    Intent extends T,
    H extends T,
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
        PasskeyRegistrationCeremonyMapping<M, Flow, Admission, Charge, Intent, H> & Extra,
        RSetup
      >;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    PasskeyCoordinatorError<E> | DatabaseError,
    Exclude<R, PasskeyPersistence> | LifecycleHooks | DatabaseRequirements | RSetup
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetPasskeyRegistration(
        database,
        options.mapping,
        configuration,
        (transaction: TransactionOf<Database>, services: PasskeyRegistrationCeremonyServices) => {
          const provided = Context.make(PasskeyPersistence, services.passkeyPersistence);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }

  return {
    ...makePasskeyWriteTarget<D, T, Extra, Synchronous>(configuration),
    makePasskeyCredentialServices: <
      Database extends D,
      S extends T,
      C extends T,
      F extends T,
      O extends T,
      H extends T,
      N,
      RSetup = never,
    >(
      database: Database,
      mapping: PasskeyMappingSource<PasskeyCredentialMapping<S, C, F, O, H, N> & Extra, RSetup>,
    ) => makeTargetPasskeyCredentials(database, mapping, configuration),
    makePasskeyEnrollmentContextServices: <
      Database extends D,
      S extends T,
      C extends T,
      F extends T,
      O extends T,
      H extends T,
      M extends T,
      N,
      RSetup = never,
    >(
      database: Database,
      mapping: PasskeyMappingSource<
        PasskeyEnrollmentContextMapping<PasskeyCredentialMapping<S, C, F, O, H, N>, M, N> & Extra,
        RSetup
      >,
    ) => makeTargetPasskeyEnrollmentContext(database, mapping, configuration),
    makePasskeyPersistenceServices: <
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
      N,
      RSetup = never,
    >(
      database: Database,
      mapping: PasskeyMappingSource<
        PasskeyPersistenceMapping<
          PasskeyCredentialMapping<S, C, F, O, H, N>,
          M,
          Flow,
          Admission,
          Charge,
          N
        > &
          Extra,
        RSetup
      >,
    ) => makeTargetPasskeyPersistence(database, mapping, configuration),
    makePasskeyRegistrationCeremonyServices: <
      Database extends D,
      M extends T,
      Flow extends T,
      Admission extends T,
      Charge extends T,
      Intent extends T,
      H extends T,
      RSetup = never,
    >(
      database: Database,
      mapping: PasskeyMappingSource<
        PasskeyRegistrationCeremonyMapping<M, Flow, Admission, Charge, Intent, H> & Extra,
        RSetup
      >,
    ) => makeTargetPasskeyRegistration(database, mapping, configuration),
    coordinatePasskeyPersistence,
    coordinatePasskeyRegistrationCeremony,
  };
};
