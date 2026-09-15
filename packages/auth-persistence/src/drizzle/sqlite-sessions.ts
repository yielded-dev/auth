import type { LifecycleHooks, HookConfigurationError } from "@yielded/auth/Hooks";
import {
  AuthenticationAuthority,
  type SessionUnavailable,
  type PendingAuthentication,
  type SessionRepository,
  type SignedSessionValidity,
  type StatefulSessionPersistence,
  type SessionStepUpPersistence,
} from "@yielded/auth/Sessions";
import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Context, Effect } from "effect";
import type { SqlError } from "effect/unstable/sql/SqlError";

import type {
  AuthenticationAuthorityMapping,
  PendingAuthenticationMapping,
  SignedSessionValidityMapping,
  StatefulSessionMapping,
} from "./session-model";
import {
  coordinateTargetAuthenticationAuthority,
  coordinateTargetPendingAuthentication,
  coordinateTargetSignedSessionValidity,
  coordinateTargetStatefulSessions,
  makeTargetAuthenticationAuthorityServices,
  makeTargetPendingAuthenticationServices,
  makeTargetSignedSessionValidityServices,
  makeTargetStatefulSessionServices,
  type SessionTargetConfiguration,
  makeTargetSessionStepUpServices,
  coordinateTargetSessionStepUp,
} from "./session-target";
import type { SuppliedService } from "./SuppliedService";

type Database =
  | EffectLibsqlDatabase<AnyRelations>
  | EffectSQLiteBunDatabase<AnyRelations>
  | EffectSQLiteDoDatabase<AnyRelations>
  | EffectSQLiteNodeDatabase<AnyRelations>
  | EffectSQLiteWasmDatabase<AnyRelations>;
type TransactionOf<D extends Database> = Parameters<Parameters<D["transaction"]>[0]>[0];

export const sqliteSessionConfiguration = (
  mode: "interactive" | "synchronous",
  standaloneGuard: Effect.Effect<void, SessionUnavailable>,
  coordinatorGuard?: Effect.Effect<void, SessionUnavailable>,
): SessionTargetConfiguration => ({
  mode,
  locking: false,
  standaloneGuard,
  ...(coordinatorGuard === undefined ? {} : { coordinatorGuard }),
});

export const makeSqliteAuthenticationAuthorityServices = <
  Claims,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  F extends AnySQLiteTable,
  P extends AnySQLiteTable,
  NativeId,
>(
  database: Database,
  mapping: AuthenticationAuthorityMapping<Claims, S, C, F, P, NativeId>,
  configuration: SessionTargetConfiguration,
) => makeTargetAuthenticationAuthorityServices<Claims>(database, mapping, configuration);

export const makeSqlitePendingAuthenticationServices = <
  Claims,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  P extends AnySQLiteTable,
  F extends AnySQLiteTable,
  NativeId,
>(
  database: Database,
  mapping: PendingAuthenticationMapping<Claims, S, C, P, F, NativeId>,
  configuration: SessionTargetConfiguration,
) => makeTargetPendingAuthenticationServices<Claims>(database, mapping, configuration);

export const makeSqliteStatefulSessionServices = <
  Claims,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  Session extends AnySQLiteTable,
  F extends AnySQLiteTable,
  P extends AnySQLiteTable,
  NativeId,
  NativeSessionId,
>(
  database: Database,
  mapping: StatefulSessionMapping<Claims, S, C, Session, F, P, NativeId, NativeSessionId>,
  configuration: SessionTargetConfiguration,
) => makeTargetStatefulSessionServices<Claims>(database, mapping, configuration);

export const makeSqliteSignedSessionValidityServices = <
  S extends AnySQLiteTable,
  T extends AnySQLiteTable,
  NativeId,
  NativeSessionId,
>(
  database: Database,
  mapping: SignedSessionValidityMapping<S, T, NativeId, NativeSessionId>,
  configuration: SessionTargetConfiguration,
) => makeTargetSignedSessionValidityServices(database, mapping, configuration);

export const coordinateSqliteAuthenticationAuthority = <
  Claims,
  D extends Database,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  F extends AnySQLiteTable,
  P extends AnySQLiteTable,
  NativeId,
  A,
  E,
  R,
>(
  database: D,
  mapping: AuthenticationAuthorityMapping<Claims, S, C, F, P, NativeId>,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: TransactionOf<D>,
    services: { readonly authenticationAuthority: AuthenticationAuthority["Service"] },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateTargetAuthenticationAuthority<Claims, TransactionOf<D>, A, E, R>(
    database,
    mapping,
    configuration,
    owner,
  );

export const coordinateSqlitePendingAuthentication = <
  Claims,
  D extends Database,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  P extends AnySQLiteTable,
  F extends AnySQLiteTable,
  NativeId,
  A,
  E,
  R,
>(
  database: D,
  mapping: PendingAuthenticationMapping<Claims, S, C, P, F, NativeId>,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: TransactionOf<D>,
    services: { readonly pendingAuthentication: PendingAuthentication<Claims> },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateTargetPendingAuthentication<Claims, TransactionOf<D>, A, E, R>(
    database,
    mapping,
    configuration,
    owner,
  );

export const coordinateSqliteStatefulSessions = <
  Claims,
  D extends Database,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  Session extends AnySQLiteTable,
  F extends AnySQLiteTable,
  P extends AnySQLiteTable,
  NativeId,
  NativeSessionId,
  A,
  E,
  R,
>(
  database: D,
  mapping: StatefulSessionMapping<Claims, S, C, Session, F, P, NativeId, NativeSessionId>,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: TransactionOf<D>,
    services: {
      readonly statefulSessionPersistence: StatefulSessionPersistence<Claims>;
      readonly sessionRepository: SessionRepository;
    },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateTargetStatefulSessions<Claims, TransactionOf<D>, A, E, R>(
    database,
    mapping,
    configuration,
    owner,
  );

export const coordinateSqliteSignedSessionValidity = <
  D extends Database,
  S extends AnySQLiteTable,
  T extends AnySQLiteTable,
  NativeId,
  NativeSessionId,
  A,
  E,
  R,
>(
  database: D,
  mapping: SignedSessionValidityMapping<S, T, NativeId, NativeSessionId>,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: TransactionOf<D>,
    services: { readonly signedSessionValidity: SignedSessionValidity },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateTargetSignedSessionValidity<TransactionOf<D>, A, E, R>(
    database,
    mapping,
    configuration,
    owner,
  );

export const makeSqliteSessionTarget = <D extends Database, Synchronous extends boolean = false>(
  configuration: SessionTargetConfiguration | ((database: D) => SessionTargetConfiguration),
) => {
  const configurationFor = (database: D) =>
    typeof configuration === "function" ? configuration(database) : configuration;

  function coordinateSessionStepUp<
    Database extends D,
    Claims,
    Id,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    I extends AnySQLiteTable,
    Session extends AnySQLiteTable,
    T extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: SessionStepUpMapping<
        NoInfer<Claims>,
        S,
        C,
        I,
        Session,
        T,
        NativeId,
        NativeSessionId
      >;
      readonly target: SuppliedService<Id, SessionStepUpPersistence<Claims>>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<Id> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    (Synchronous extends true ? never : Exclude<R, Id>) | LifecycleHooks | DatabaseRequirements
  >;
  function coordinateSessionStepUp<
    Database extends D,
    Claims,
    Id,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    I extends AnySQLiteTable,
    Session extends AnySQLiteTable,
    T extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
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
      readonly mapping: SessionStepUpMapping<
        NoInfer<Claims>,
        S,
        C,
        I,
        Session,
        T,
        NativeId,
        NativeSessionId
      >;
      readonly target: SuppliedService<Id, SessionStepUpPersistence<Claims>>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<Id | TxId> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, Id | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateSessionStepUp<
    Database extends D,
    Claims,
    Id,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    I extends AnySQLiteTable,
    Session extends AnySQLiteTable,
    T extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
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
      readonly mapping: SessionStepUpMapping<
        NoInfer<Claims>,
        S,
        C,
        I,
        Session,
        T,
        NativeId,
        NativeSessionId
      >;
      readonly target: SuppliedService<Id, SessionStepUpPersistence<Claims>>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    Exclude<R, Id> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateSqliteSessionStepUp(
        database,
        options.mapping,
        options.target,
        configurationFor(database),
        (
          transaction: TransactionOf<Database>,
          services: { readonly sessionStepUpPersistence: SessionStepUpPersistence<Claims> },
        ) => {
          const provided = Context.make(options.target, services.sessionStepUpPersistence);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinateAuthenticationAuthority<
    Database extends D,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    F extends AnySQLiteTable,
    P extends AnySQLiteTable,
    NativeId,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: AuthenticationAuthorityMapping<Claims, S, C, F, P, NativeId>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<AuthenticationAuthority> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, AuthenticationAuthority>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateAuthenticationAuthority<
    Database extends D,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    F extends AnySQLiteTable,
    P extends AnySQLiteTable,
    NativeId,
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
      readonly mapping: AuthenticationAuthorityMapping<Claims, S, C, F, P, NativeId>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<AuthenticationAuthority | TxId> : R
    >,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, AuthenticationAuthority | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateAuthenticationAuthority<
    Database extends D,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    F extends AnySQLiteTable,
    P extends AnySQLiteTable,
    NativeId,
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
      readonly mapping: AuthenticationAuthorityMapping<Claims, S, C, F, P, NativeId>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    Exclude<R, AuthenticationAuthority> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateSqliteAuthenticationAuthority(
        database,
        options.mapping,
        configurationFor(database),
        (
          transaction: TransactionOf<Database>,
          services: { readonly authenticationAuthority: AuthenticationAuthority["Service"] },
        ) => {
          const provided = Context.make(AuthenticationAuthority, services.authenticationAuthority);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinatePendingAuthentication<
    Database extends D,
    TargetId,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    P extends AnySQLiteTable,
    F extends AnySQLiteTable,
    NativeId,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: PendingAuthenticationMapping<NoInfer<Claims>, S, C, P, F, NativeId>;
      readonly target: SuppliedService<TargetId, PendingAuthentication<Claims>>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TargetId> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinatePendingAuthentication<
    Database extends D,
    TargetId,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    P extends AnySQLiteTable,
    F extends AnySQLiteTable,
    NativeId,
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
      readonly mapping: PendingAuthenticationMapping<NoInfer<Claims>, S, C, P, F, NativeId>;
      readonly target: SuppliedService<TargetId, PendingAuthentication<Claims>>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TargetId | TxId> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinatePendingAuthentication<
    Database extends D,
    TargetId,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    P extends AnySQLiteTable,
    F extends AnySQLiteTable,
    NativeId,
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
      readonly mapping: PendingAuthenticationMapping<NoInfer<Claims>, S, C, P, F, NativeId>;
      readonly target: SuppliedService<TargetId, PendingAuthentication<Claims>>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateSqlitePendingAuthentication(
        database,
        options.mapping,
        configurationFor(database),
        (
          transaction: TransactionOf<Database>,
          services: { readonly pendingAuthentication: PendingAuthentication<Claims> },
        ) => {
          const provided = Context.make(options.target, services.pendingAuthentication);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinateStatefulSessions<
    Database extends D,
    PersistenceId,
    RepositoryId,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    Session extends AnySQLiteTable,
    F extends AnySQLiteTable,
    P extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: StatefulSessionMapping<
        NoInfer<Claims>,
        S,
        C,
        Session,
        F,
        P,
        NativeId,
        NativeSessionId
      >;
      readonly persistence: SuppliedService<PersistenceId, StatefulSessionPersistence<Claims>>;
      readonly repository: SuppliedService<RepositoryId, SessionRepository>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<PersistenceId | RepositoryId> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PersistenceId | RepositoryId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateStatefulSessions<
    Database extends D,
    PersistenceId,
    RepositoryId,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    Session extends AnySQLiteTable,
    F extends AnySQLiteTable,
    P extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
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
      readonly mapping: StatefulSessionMapping<
        NoInfer<Claims>,
        S,
        C,
        Session,
        F,
        P,
        NativeId,
        NativeSessionId
      >;
      readonly persistence: SuppliedService<PersistenceId, StatefulSessionPersistence<Claims>>;
      readonly repository: SuppliedService<RepositoryId, SessionRepository>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<
      A,
      E,
      Synchronous extends true ? NoInfer<PersistenceId | RepositoryId | TxId> : R
    >,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PersistenceId | RepositoryId | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateStatefulSessions<
    Database extends D,
    PersistenceId,
    RepositoryId,
    Claims,
    S extends AnySQLiteTable,
    C extends AnySQLiteTable,
    Session extends AnySQLiteTable,
    F extends AnySQLiteTable,
    P extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
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
      readonly mapping: StatefulSessionMapping<
        NoInfer<Claims>,
        S,
        C,
        Session,
        F,
        P,
        NativeId,
        NativeSessionId
      >;
      readonly persistence: SuppliedService<PersistenceId, StatefulSessionPersistence<Claims>>;
      readonly repository: SuppliedService<RepositoryId, SessionRepository>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    Exclude<R, PersistenceId | RepositoryId> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateSqliteStatefulSessions(
        database,
        options.mapping,
        configurationFor(database),
        (
          transaction: TransactionOf<Database>,
          services: {
            readonly statefulSessionPersistence: StatefulSessionPersistence<Claims>;
            readonly sessionRepository: SessionRepository;
          },
        ) => {
          const provided = Context.make(
            options.persistence,
            services.statefulSessionPersistence,
          ).pipe(Context.add(options.repository, services.sessionRepository));

          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinateSignedSessionValidity<
    Database extends D,
    TargetId,
    S extends AnySQLiteTable,
    T extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
    A,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: SignedSessionValidityMapping<S, T, NativeId, NativeSessionId>;
      readonly target: SuppliedService<TargetId, SignedSessionValidity>;
      readonly transaction?: never;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TargetId> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateSignedSessionValidity<
    Database extends D,
    TargetId,
    S extends AnySQLiteTable,
    T extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
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
      readonly mapping: SignedSessionValidityMapping<S, T, NativeId, NativeSessionId>;
      readonly target: SuppliedService<TargetId, SignedSessionValidity>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, Synchronous extends true ? NoInfer<TargetId | TxId> : R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinateSignedSessionValidity<
    Database extends D,
    TargetId,
    S extends AnySQLiteTable,
    T extends AnySQLiteTable,
    NativeId,
    NativeSessionId,
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
      readonly mapping: SignedSessionValidityMapping<S, T, NativeId, NativeSessionId>;
      readonly target: SuppliedService<TargetId, SignedSessionValidity>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<A, E, R>,
  ): Effect.Effect<
    A,
    E | SessionUnavailable | HookConfigurationError | SqlError | DatabaseError,
    Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateSqliteSignedSessionValidity(
        database,
        options.mapping,
        configurationFor(database),
        (
          transaction: TransactionOf<Database>,
          services: { readonly signedSessionValidity: SignedSessionValidity },
        ) => {
          const provided = Context.make(options.target, services.signedSessionValidity);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }

  return {
    makeSessionStepUpServices: <
      Claims,
      Id,
      S extends AnySQLiteTable,
      C extends AnySQLiteTable,
      I extends AnySQLiteTable,
      Session extends AnySQLiteTable,
      T extends AnySQLiteTable,
      NativeId,
      NativeSessionId,
    >(
      database: D,
      mapping: SessionStepUpMapping<
        NoInfer<Claims>,
        S,
        C,
        I,
        Session,
        T,
        NativeId,
        NativeSessionId
      >,
      target: Context.Service<Id, SessionStepUpPersistence<Claims>>,
    ) => makeSqliteSessionStepUpServices(database, mapping, target, configurationFor(database)),
    coordinateSessionStepUp,
    makeAuthenticationAuthorityServices: <
      Claims,
      S extends AnySQLiteTable,
      C extends AnySQLiteTable,
      F extends AnySQLiteTable,
      P extends AnySQLiteTable,
      NativeId,
    >(
      database: D,
      mapping: AuthenticationAuthorityMapping<Claims, S, C, F, P, NativeId>,
    ) => makeSqliteAuthenticationAuthorityServices(database, mapping, configurationFor(database)),
    makePendingAuthenticationServices: <
      Claims,
      S extends AnySQLiteTable,
      C extends AnySQLiteTable,
      P extends AnySQLiteTable,
      F extends AnySQLiteTable,
      NativeId,
    >(
      database: D,
      mapping: PendingAuthenticationMapping<Claims, S, C, P, F, NativeId>,
    ) => makeSqlitePendingAuthenticationServices(database, mapping, configurationFor(database)),
    makeStatefulSessionServices: <
      Claims,
      S extends AnySQLiteTable,
      C extends AnySQLiteTable,
      Session extends AnySQLiteTable,
      F extends AnySQLiteTable,
      P extends AnySQLiteTable,
      NativeId,
      NativeSessionId,
    >(
      database: D,
      mapping: StatefulSessionMapping<Claims, S, C, Session, F, P, NativeId, NativeSessionId>,
    ) => makeSqliteStatefulSessionServices(database, mapping, configurationFor(database)),
    makeSignedSessionValidityServices: <
      S extends AnySQLiteTable,
      T extends AnySQLiteTable,
      NativeId,
      NativeSessionId,
    >(
      database: D,
      mapping: SignedSessionValidityMapping<S, T, NativeId, NativeSessionId>,
    ) => makeSqliteSignedSessionValidityServices(database, mapping, configurationFor(database)),
    coordinateAuthenticationAuthority,
    coordinatePendingAuthentication,
    coordinateStatefulSessions,
    coordinateSignedSessionValidity,
  };
};

import type { SessionStepUpMapping } from "./step-up-model";

export const makeSqliteSessionStepUpServices = <
  Claims,
  Id,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  I extends AnySQLiteTable,
  Session extends AnySQLiteTable,
  T extends AnySQLiteTable,
  NativeId,
  NativeSessionId,
>(
  database: Database,
  mapping: SessionStepUpMapping<NoInfer<Claims>, S, C, I, Session, T, NativeId, NativeSessionId>,
  target: Context.Service<Id, SessionStepUpPersistence<Claims>>,
  configuration: SessionTargetConfiguration,
) => makeTargetSessionStepUpServices(database, mapping, target, configuration);

export const coordinateSqliteSessionStepUp = <
  Claims,
  Id,
  S extends AnySQLiteTable,
  C extends AnySQLiteTable,
  I extends AnySQLiteTable,
  Session extends AnySQLiteTable,
  T extends AnySQLiteTable,
  NativeId,
  NativeSessionId,
  D extends Database,
  A,
  E,
  R,
>(
  database: D,
  mapping: SessionStepUpMapping<NoInfer<Claims>, S, C, I, Session, T, NativeId, NativeSessionId>,
  target: Context.Service<Id, SessionStepUpPersistence<Claims>>,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: TransactionOf<D>,
    services: { readonly sessionStepUpPersistence: SessionStepUpPersistence<Claims> },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinateTargetSessionStepUp<Claims, Id, TransactionOf<D>, A, E, R>(
    database,
    mapping,
    target,
    configuration,
    owner,
  );
