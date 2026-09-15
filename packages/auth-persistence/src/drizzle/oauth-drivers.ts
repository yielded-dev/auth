import type { LifecycleHooks } from "@yielded/auth/Hooks";
import {
  OAuthAccountsPersistence,
  OAuthRegistrationIntents,
  OAuthSignInPersistence,
} from "@yielded/auth/OAuth";
import type { Table } from "drizzle-orm";
import { Effect, Context } from "effect";

import { makeOAuthConnectedTarget } from "./oauth-connected-drivers";
import type {
  OAuthAccountsMapping,
  OAuthRegistrationAuthority,
  OAuthRegistrationIntentMapping,
  OAuthRegistrationMapping,
  OAuthSignInMapping,
} from "./oauth-model";
import {
  type OAuthCoordinatorError,
  coordinateTargetOAuthAccounts,
  coordinateTargetOAuthSignIn,
  coordinateTargetOAuthRegistrationIntents,
  coordinateTargetOAuthRegistration,
  makeTargetOAuthRegistrationIntentServices,
  makeTargetOAuthRegistrationServices,
  makeTargetOAuthSignInServices,
  makeTargetOAuthAccountsServices,
  type OAuthTargetConfiguration,
} from "./oauth-target";
import type { SuppliedService } from "./SuppliedService";

// oxlint-disable-next-line no-explicit-any -- inspect the installed generic transaction signature without erasing its callback parameter.
type TransactionOf<D> = D extends { readonly transaction: (...args: any[]) => any }
  ? Parameters<Parameters<D["transaction"]>[0]>[0]
  : never;

/** Driver-specific entry points instantiate both the database and table family. */
export const makeOAuthTarget = <D, T extends Table, Synchronous extends boolean = false>(
  configuration: OAuthTargetConfiguration,
) => {
  function coordinateOAuthSignIn<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthSignInMapping<S, O, C, AC, F, N>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<OAuthSignInPersistence> : R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthSignInPersistence>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthSignIn<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthSignInMapping<S, O, C, AC, F, N>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<OAuthSignInPersistence | TxId> : R
    >,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthSignInPersistence | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthSignIn<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthSignInMapping<S, O, C, AC, F, N>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    Exclude<R, OAuthSignInPersistence> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetOAuthSignIn<
        TransactionOf<Database>,
        A,
        E,
        Exclude<R, OAuthSignInPersistence>
      >(
        database,
        options.mapping,
        configuration,
        (
          transaction: TransactionOf<Database>,
          services: { readonly oauthSignInPersistence: OAuthSignInPersistence["Service"] },
        ) => {
          const provided = Context.make(OAuthSignInPersistence, services.oauthSignInPersistence);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinateOAuthRegistrationIntents<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    TA extends T,
    I extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthRegistrationIntentMapping<S, O, C, AC, F, TA, I, N>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<OAuthRegistrationIntents> : R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthRegistrationIntents>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthRegistrationIntents<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    TA extends T,
    I extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthRegistrationIntentMapping<S, O, C, AC, F, TA, I, N>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<OAuthRegistrationIntents | TxId> : R
    >,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthRegistrationIntents | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthRegistrationIntents<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    TA extends T,
    I extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthRegistrationIntentMapping<S, O, C, AC, F, TA, I, N>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    Exclude<R, OAuthRegistrationIntents> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetOAuthRegistrationIntents<
        TransactionOf<Database>,
        A,
        E,
        Exclude<R, OAuthRegistrationIntents>
      >(
        database,
        options.mapping,
        configuration,
        (
          transaction: TransactionOf<Database>,
          services: { readonly oauthRegistrationIntents: OAuthRegistrationIntents["Service"] },
        ) => {
          const provided = Context.make(
            OAuthRegistrationIntents,
            services.oauthRegistrationIntents,
          );

          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinateOAuthAccounts<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    TA extends T,
    U extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthAccountsMapping<S, O, C, AC, F, TA, U, N>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<OAuthAccountsPersistence> : R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthAccountsPersistence>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthAccounts<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    TA extends T,
    U extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthAccountsMapping<S, O, C, AC, F, TA, U, N>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<OAuthAccountsPersistence | TxId> : R
    >,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, OAuthAccountsPersistence | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthAccounts<
    Database extends D,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    F extends T,
    TA extends T,
    U extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthAccountsMapping<S, O, C, AC, F, TA, U, N>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    Exclude<R, OAuthAccountsPersistence> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetOAuthAccounts<
        TransactionOf<Database>,
        A,
        E,
        Exclude<R, OAuthAccountsPersistence>
      >(
        database,
        options.mapping,
        configuration,
        (
          transaction: TransactionOf<Database>,
          services: { readonly oauthAccountsPersistence: OAuthAccountsPersistence["Service"] },
        ) => {
          const provided = Context.make(
            OAuthAccountsPersistence,
            services.oauthAccountsPersistence,
          );

          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinateOAuthRegistration<
    Database extends D,
    TargetId,
    Registration,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    TA extends T,
    I extends T,
    Rq extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthRegistrationMapping<NoInfer<Registration>, S, O, C, AC, TA, I, Rq, N>;
      readonly target: SuppliedService<TargetId, OAuthRegistrationAuthority<Registration>>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TargetId> : R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthRegistration<
    Database extends D,
    TargetId,
    Registration,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    TA extends T,
    I extends T,
    Rq extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthRegistrationMapping<NoInfer<Registration>, S, O, C, AC, TA, I, Rq, N>;
      readonly target: SuppliedService<TargetId, OAuthRegistrationAuthority<Registration>>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TargetId | TxId> : R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateOAuthRegistration<
    Database extends D,
    TargetId,
    Registration,
    S extends T,
    O extends T,
    C extends T,
    AC extends T,
    TA extends T,
    I extends T,
    Rq extends T,
    N,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: OAuthRegistrationMapping<NoInfer<Registration>, S, O, C, AC, TA, I, Rq, N>;
      readonly target: SuppliedService<TargetId, OAuthRegistrationAuthority<Registration>>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    OAuthCoordinatorError<E> | DatabaseError,
    Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateTargetOAuthRegistration<
        Registration,
        TransactionOf<Database>,
        A,
        E,
        Exclude<R, TargetId>
      >(
        database,
        options.mapping,
        configuration,
        (
          transaction: TransactionOf<Database>,
          services: { readonly registrationAuthority: OAuthRegistrationAuthority<Registration> },
        ) => {
          const provided = Context.make(options.target, services.registrationAuthority);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }

  return {
    ...makeOAuthConnectedTarget<D, T, {}, Synchronous>(configuration),
    coordinateOAuthSignIn,
    coordinateOAuthRegistrationIntents,
    coordinateOAuthAccounts,
    makeOAuthAccountsServices: <
      S extends T,
      O extends T,
      C extends T,
      AC extends T,
      F extends T,
      TA extends T,
      U extends T,
      N,
    >(
      database: D,
      mapping: OAuthAccountsMapping<S, O, C, AC, F, TA, U, N>,
    ) => makeTargetOAuthAccountsServices(database, mapping, configuration),
    makeOAuthSignInServices: <S extends T, O extends T, C extends T, AC extends T, F extends T, N>(
      database: D,
      mapping: OAuthSignInMapping<S, O, C, AC, F, N>,
    ) => makeTargetOAuthSignInServices(database, mapping, configuration),
    makeOAuthRegistrationIntentServices: <
      S extends T,
      O extends T,
      C extends T,
      AC extends T,
      F extends T,
      TA extends T,
      I extends T,
      N,
    >(
      database: D,
      mapping: OAuthRegistrationIntentMapping<S, O, C, AC, F, TA, I, N>,
    ) => makeTargetOAuthRegistrationIntentServices(database, mapping, configuration),
    makeOAuthRegistrationServices: <
      Registration,
      S extends T,
      O extends T,
      C extends T,
      AC extends T,
      TA extends T,
      I extends T,
      R extends T,
      N,
    >(
      database: D,
      mapping: OAuthRegistrationMapping<Registration, S, O, C, AC, TA, I, R, N>,
    ) => makeTargetOAuthRegistrationServices<Registration>(database, mapping, configuration),
    coordinateOAuthRegistration,
  };
};
