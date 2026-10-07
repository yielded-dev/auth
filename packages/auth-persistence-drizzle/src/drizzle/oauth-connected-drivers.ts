import type { LifecycleHooks } from "@yielded/auth/Hooks";
import type { OAuthUnavailable } from "@yielded/auth/OAuth";
import { OAuthConnectedPersistence, OAuthConnectedRevocations } from "@yielded/auth/OAuth";
import type { Table } from "drizzle-orm";
import { type Crypto, Effect, Context } from "effect";

import type { D1BatchStatements } from "./D1BatchStatements";
import { NativeDatabase, nativeDatabase } from "./native-database";
import type {
  OAuthConnectedMapping,
  OAuthConnectedRevocationMapping,
} from "./oauth-connected-model";
import {
  coordinateTargetOAuthConnected,
  coordinateTargetOAuthConnectedRevocations,
  makeTargetOAuthConnectedServices,
  makeTargetOAuthConnectedRevocationServices,
} from "./oauth-connected-target";
import { type OAuthCoordinatorError, type OAuthTargetConfiguration } from "./oauth-target";
import type { SuppliedService } from "./SuppliedService";
// oxlint-disable-next-line no-explicit-any -- inspect the actual installed native transaction callback without erasing it.
type TransactionOf<D> = D extends { readonly transaction: (...args: any[]) => any }
  ? Parameters<Parameters<D["transaction"]>[0]>[0]
  : never;

export const makeOAuthConnectedTarget = <
  DatabaseId,
  Database,
  Family extends Table,
  Extra = {},
  Synchronous extends boolean = false,
>(
  databaseService: Context.Service<DatabaseId, Database>,
  configuration: OAuthTargetConfiguration,
) => {
  function coordinateOAuthConnected<
    D extends Database,
    S extends Family,
    AC extends Family,
    O extends Family,
    F extends Family,
    G extends Family,
    N,
    J extends Family,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthConnectedMapping<S, AC, O, F, G, N, J> & Extra;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<OAuthConnectedPersistence> : R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthConnectedPersistence>)
    | Crypto.Crypto
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthConnected<
    D extends Database,
    S extends Family,
    AC extends Family,
    O extends Family,
    F extends Family,
    G extends Family,
    N,
    J extends Family,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthConnectedMapping<S, AC, O, F, G, N, J> & Extra;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<OAuthConnectedPersistence | TxId> : R
    >,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthConnectedPersistence | TxId>)
    | Crypto.Crypto
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthConnected<
    D extends Database,
    S extends Family,
    AC extends Family,
    O extends Family,
    F extends Family,
    G extends Family,
    N,
    J extends Family,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthConnectedMapping<S, AC, O, F, G, N, J> & Extra;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    Exclude<R, OAuthConnectedPersistence> | Crypto.Crypto | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(nativeDatabase(acquire), (database) =>
      coordinateTargetOAuthConnected<TransactionOf<D>, A, E, Exclude<R, OAuthConnectedPersistence>>(
        database,
        options.mapping,
        configuration,
        (
          transaction: TransactionOf<D>,
          services: { readonly oauthConnectedPersistence: OAuthConnectedPersistence["Service"] },
        ) => {
          const provided = Context.make(
            OAuthConnectedPersistence,
            services.oauthConnectedPersistence,
          );

          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ).pipe(Effect.provideService(NativeDatabase, database)),
    );
  }
  function coordinateOAuthConnectedRevocations<
    D extends Database,
    O extends Family,
    F extends Family,
    J extends Family,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthConnectedRevocationMapping<O, F, J, N> & Extra;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<OAuthConnectedRevocations> : R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthConnectedRevocations>)
    | Crypto.Crypto
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthConnectedRevocations<
    D extends Database,
    O extends Family,
    F extends Family,
    J extends Family,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthConnectedRevocationMapping<O, F, J, N> & Extra;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<OAuthConnectedRevocations | TxId> : R
    >,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthConnectedRevocations | TxId>)
    | Crypto.Crypto
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthConnectedRevocations<
    D extends Database,
    O extends Family,
    F extends Family,
    J extends Family,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthConnectedRevocationMapping<O, F, J, N> & Extra;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    Exclude<R, OAuthConnectedRevocations> | Crypto.Crypto | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(nativeDatabase(acquire), (database) =>
      coordinateTargetOAuthConnectedRevocations<
        TransactionOf<D>,
        A,
        E,
        Exclude<R, OAuthConnectedRevocations>
      >(
        database,
        options.mapping,
        configuration,
        (
          transaction: TransactionOf<D>,
          services: { readonly oauthConnectedRevocations: OAuthConnectedRevocations["Service"] },
        ) => {
          const provided = Context.make(
            OAuthConnectedRevocations,
            services.oauthConnectedRevocations,
          );

          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ).pipe(Effect.provideService(NativeDatabase, database)),
    );
  }

  return {
    makeOAuthConnectedServices: <
      S extends Family,
      AC extends Family,
      O extends Family,
      F extends Family,
      G extends Family,
      N,
      J extends Family = never,
    >(
      mapping: OAuthConnectedMapping<S, AC, O, F, G, N, J> & Extra,
    ) =>
      makeTargetOAuthConnectedServices(mapping, configuration).pipe(
        Effect.provideServiceEffect(NativeDatabase, nativeDatabase(databaseService)),
      ),
    makeOAuthConnectedRevocationServices: <O extends Family, F extends Family, J extends Family, N>(
      mapping: OAuthConnectedRevocationMapping<O, F, J, N> & Extra,
    ) =>
      makeTargetOAuthConnectedRevocationServices(mapping, configuration).pipe(
        Effect.provideServiceEffect(NativeDatabase, nativeDatabase(databaseService)),
      ),
    coordinateOAuthConnected,
    coordinateOAuthConnectedRevocations,
  };
};

export const makeD1OAuthConnectedTarget = <DatabaseId, Database, Family extends Table, Extra>(
  databaseService: Context.Service<DatabaseId, Database>,
  configuration: OAuthTargetConfiguration,
) => {
  function coordinateOAuthConnected<
    S extends Family,
    AC extends Family,
    O extends Family,
    F extends Family,
    G extends Family,
    N,
    J extends Family,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthConnectedMapping<S, AC, O, F, G, N, J> & Extra;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | Exclude<Exclude<R, OAuthConnectedPersistence>, D1BatchStatements>
    | Crypto.Crypto
    | LifecycleHooks
    | DatabaseRequirements
  > {
    return Effect.flatMap(nativeDatabase(acquire), (database) =>
      coordinateTargetOAuthConnected<
        Database,
        A,
        E | OAuthUnavailable,
        Exclude<R, OAuthConnectedPersistence>
      >(database, options.mapping, configuration, (_tx, services) =>
        Effect.provideService(body, OAuthConnectedPersistence, services.oauthConnectedPersistence),
      ).pipe(Effect.provideService(NativeDatabase, database)),
    );
  }
  function coordinateOAuthConnectedRevocations<
    O extends Family,
    F extends Family,
    J extends Family,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: { readonly mapping: OAuthConnectedRevocationMapping<O, F, J, N> & Extra },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | Exclude<Exclude<R, OAuthConnectedRevocations>, D1BatchStatements>
    | Crypto.Crypto
    | LifecycleHooks
    | DatabaseRequirements
  > {
    return Effect.flatMap(nativeDatabase(acquire), (database) =>
      coordinateTargetOAuthConnectedRevocations<
        Database,
        A,
        E | OAuthUnavailable,
        Exclude<R, OAuthConnectedRevocations>
      >(database, options.mapping, configuration, (_tx, services) =>
        Effect.provideService(body, OAuthConnectedRevocations, services.oauthConnectedRevocations),
      ).pipe(Effect.provideService(NativeDatabase, database)),
    );
  }

  return {
    ...makeOAuthConnectedTarget<DatabaseId, Database, Family, Extra>(
      databaseService,
      configuration,
    ),
    coordinateOAuthConnected,
    coordinateOAuthConnectedRevocations,
  };
};
