import type { LifecycleHooks, HookConfigurationError } from "@yielded/auth/Hooks";
import { type PasswordUnavailable, PasswordPersistence } from "@yielded/auth/Password";
/* oxlint-disable no-explicit-any -- proof mapping tables are independently typed by the proof owner; this driver forwards them unchanged to the shared target. */
import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";
import type { EffectSQLiteDoDatabase as DODatabase } from "drizzle-orm/effect-sqlite-do";
import type { EffectSQLiteNodeDatabase as NodeDatabase } from "drizzle-orm/effect-sqlite-node";
import type { EffectSQLiteWasmDatabase as WasmDatabase } from "drizzle-orm/effect-sqlite-wasm";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Effect, Context } from "effect";
import type { SqlError } from "effect/unstable/sql/SqlError";

import type { PasswordPersistenceMapping, PasswordRegistrationMapping } from "./password-model";
import type { PasswordRegistrationAuthority } from "./password-registration";
import type { PasswordSqlQuery } from "./password-sql";
import {
  coordinateTargetPasswordPersistence,
  coordinateTargetPasswordRegistration,
  makeTargetPasswordPersistenceServices,
  makeTargetPasswordRegistrationServices,
  type PasswordTargetConfiguration,
} from "./password-target";
import type { ProofPersistenceMapping } from "./proof-model";
import type { ProofSqlQuery } from "./proof-sql";
import type { SuppliedService } from "./SuppliedService";

export type SqlitePasswordDatabase =
  | NodeDatabase<AnyRelations>
  | EffectSQLiteBunDatabase<AnyRelations>
  | EffectLibsqlDatabase<AnyRelations>
  | WasmDatabase<AnyRelations>
  | DODatabase<AnyRelations>;

type TransactionOf<D extends SqlitePasswordDatabase> = Parameters<
  Parameters<D["transaction"]>[0]
>[0];

export const sqlitePasswordConfiguration = (
  mode: "interactive" | "synchronous",
  standaloneGuard: PasswordTargetConfiguration["standaloneGuard"],
  proofStandaloneGuard: PasswordTargetConfiguration["proof"]["standaloneGuard"],
  coordinatorGuard?: PasswordTargetConfiguration["coordinatorGuard"],
): PasswordTargetConfiguration => ({
  mode,
  locking: false,
  standaloneGuard,
  ...(coordinatorGuard === undefined ? {} : { coordinatorGuard }),
  insertIfAbsent: (query: PasswordSqlQuery) => query.onConflictDoNothing(),
  generatedSubjectRows: (query: PasswordSqlQuery) => query.returning(),
  proof: {
    mode,
    locking: false,
    standaloneGuard: proofStandaloneGuard,
    insertIfAbsent: (query: ProofSqlQuery) => query.onConflictDoNothing(),
  },
});

type Mapping<
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  A extends AnySQLiteTable,
  RS extends AnySQLiteTable,
  CE extends AnySQLiteTable,
  M extends AnySQLiteTable,
  NativeId,
> = PasswordPersistenceMapping<S, I, C, AC, A, RS, CE, M, NativeId>;

export const makeSqlitePasswordPersistenceServices = <
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  A extends AnySQLiteTable,
  RS extends AnySQLiteTable,
  CE extends AnySQLiteTable,
  M extends AnySQLiteTable,
  NativeId,
>(
  database: SqlitePasswordDatabase,
  mapping: Mapping<S, I, C, AC, A, RS, CE, M, NativeId>,
  configuration: PasswordTargetConfiguration,
  proofMapping?: ProofPersistenceMapping<
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any,
    any
  >,
) => makeTargetPasswordPersistenceServices(database, mapping, configuration, proofMapping);

export const coordinateSqlitePasswordPersistence = <
  D extends SqlitePasswordDatabase,
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  A extends AnySQLiteTable,
  RS extends AnySQLiteTable,
  CE extends AnySQLiteTable,
  M extends AnySQLiteTable,
  NativeId,
  PM extends
    | ProofPersistenceMapping<any, any, any, any, any, any, any, any, any, any, any, any>
    | undefined,
  Out,
  E,
  R,
>(
  database: D,
  mapping: Mapping<S, I, C, AC, A, RS, CE, M, NativeId>,
  configuration: PasswordTargetConfiguration,
  proofMapping: PM,
  owner: (
    transaction: TransactionOf<D>,
    services: { readonly passwordPersistence: PasswordPersistence["Service"] },
  ) => Effect.Effect<Out, E, R>,
) =>
  coordinateTargetPasswordPersistence<TransactionOf<D>, Out, E, R>(
    database,
    mapping,
    configuration,
    proofMapping,
    owner,
  );

export const makeSqlitePasswordRegistrationServices = <
  Registration,
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  Rq extends AnySQLiteTable,
  NativeId,
>(
  database: SqlitePasswordDatabase,
  mapping: PasswordRegistrationMapping<Registration, S, I, C, AC, Rq, NativeId>,
  configuration: PasswordTargetConfiguration,
) => makeTargetPasswordRegistrationServices<Registration>(database, mapping, configuration);

export const coordinateSqlitePasswordRegistration = <
  Registration,
  D extends SqlitePasswordDatabase,
  S extends AnySQLiteTable,
  I extends AnySQLiteTable,
  C extends AnySQLiteTable,
  AC extends AnySQLiteTable,
  Rq extends AnySQLiteTable,
  NativeId,
  Out,
  E,
  R,
>(
  database: D,
  mapping: PasswordRegistrationMapping<Registration, S, I, C, AC, Rq, NativeId>,
  configuration: PasswordTargetConfiguration,
  owner: (
    transaction: TransactionOf<D>,
    services: { readonly registrationAuthority: PasswordRegistrationAuthority<Registration> },
  ) => Effect.Effect<Out, E, R>,
) =>
  coordinateTargetPasswordRegistration<Registration, TransactionOf<D>, Out, E, R>(
    database,
    mapping,
    configuration,
    owner,
  );

export const makeSqlitePasswordTarget = <
  D extends SqlitePasswordDatabase,
  Synchronous extends boolean = false,
>(
  configuration: PasswordTargetConfiguration | ((database: D) => PasswordTargetConfiguration),
) => {
  const configurationFor = (database: D) =>
    typeof configuration === "function" ? configuration(database) : configuration;

  function coordinatePasswordPersistence<
    Database extends D,
    S extends AnySQLiteTable,
    I extends AnySQLiteTable,
    C extends AnySQLiteTable,
    AC extends AnySQLiteTable,
    A extends AnySQLiteTable,
    RS extends AnySQLiteTable,
    CE extends AnySQLiteTable,
    M extends AnySQLiteTable,
    NativeId,
    PM extends
      | ProofPersistenceMapping<any, any, any, any, any, any, any, any, any, any, any, any>
      | undefined,
    Out,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: Mapping<S, I, C, AC, A, RS, CE, M, NativeId>;
      readonly proofMapping?: PM;
      readonly transaction?: never;
    },
    body: Effect.Effect<Out, E, Synchronous extends true ? NoInfer<PasswordPersistence> : R>,
  ): Effect.Effect<
    Out,
    E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasswordPersistence>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinatePasswordPersistence<
    Database extends D,
    S extends AnySQLiteTable,
    I extends AnySQLiteTable,
    C extends AnySQLiteTable,
    AC extends AnySQLiteTable,
    A extends AnySQLiteTable,
    RS extends AnySQLiteTable,
    CE extends AnySQLiteTable,
    M extends AnySQLiteTable,
    NativeId,
    PM extends
      | ProofPersistenceMapping<any, any, any, any, any, any, any, any, any, any, any, any>
      | undefined,
    Out,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: Mapping<S, I, C, AC, A, RS, CE, M, NativeId>;
      readonly proofMapping?: PM;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<Out, E, Synchronous extends true ? NoInfer<PasswordPersistence | TxId> : R>,
  ): Effect.Effect<
    Out,
    E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, PasswordPersistence | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinatePasswordPersistence<
    Database extends D,
    S extends AnySQLiteTable,
    I extends AnySQLiteTable,
    C extends AnySQLiteTable,
    AC extends AnySQLiteTable,
    A extends AnySQLiteTable,
    RS extends AnySQLiteTable,
    CE extends AnySQLiteTable,
    M extends AnySQLiteTable,
    NativeId,
    PM extends
      | ProofPersistenceMapping<any, any, any, any, any, any, any, any, any, any, any, any>
      | undefined,
    Out,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: Mapping<S, I, C, AC, A, RS, CE, M, NativeId>;
      readonly proofMapping?: PM;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<Out, E, R>,
  ): Effect.Effect<
    Out,
    E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
    Exclude<R, PasswordPersistence> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateSqlitePasswordPersistence(
        database,
        options.mapping,
        configurationFor(database),
        options.proofMapping,
        (
          transaction: TransactionOf<Database>,
          services: { readonly passwordPersistence: PasswordPersistence["Service"] },
        ) => {
          const provided = Context.make(PasswordPersistence, services.passwordPersistence);
          const work = Effect.provideContext(body, provided);

          return options.transaction === undefined
            ? work
            : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
        },
      ),
    );
  }
  function coordinatePasswordRegistration<
    Database extends D,
    TargetId,
    Registration,
    S extends AnySQLiteTable,
    I extends AnySQLiteTable,
    C extends AnySQLiteTable,
    AC extends AnySQLiteTable,
    Rq extends AnySQLiteTable,
    NativeId,
    Out,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: PasswordRegistrationMapping<
        NoInfer<Registration>,
        S,
        I,
        C,
        AC,
        Rq,
        NativeId
      >;
      readonly target: SuppliedService<TargetId, PasswordRegistrationAuthority<Registration>>;
      readonly transaction?: never;
    },
    body: Effect.Effect<Out, E, Synchronous extends true ? NoInfer<TargetId> : R>,
  ): Effect.Effect<
    Out,
    E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinatePasswordRegistration<
    Database extends D,
    TargetId,
    Registration,
    S extends AnySQLiteTable,
    I extends AnySQLiteTable,
    C extends AnySQLiteTable,
    AC extends AnySQLiteTable,
    Rq extends AnySQLiteTable,
    NativeId,
    Out,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: PasswordRegistrationMapping<
        NoInfer<Registration>,
        S,
        I,
        C,
        AC,
        Rq,
        NativeId
      >;
      readonly target: SuppliedService<TargetId, PasswordRegistrationAuthority<Registration>>;
      readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<Out, E, Synchronous extends true ? NoInfer<TargetId | TxId> : R>,
  ): Effect.Effect<
    Out,
    E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
    | (Synchronous extends true ? never : Exclude<R, TargetId | TxId>)
    | LifecycleHooks
    | DatabaseRequirements
  >;
  function coordinatePasswordRegistration<
    Database extends D,
    TargetId,
    Registration,
    S extends AnySQLiteTable,
    I extends AnySQLiteTable,
    C extends AnySQLiteTable,
    AC extends AnySQLiteTable,
    Rq extends AnySQLiteTable,
    NativeId,
    Out,
    E,
    R,
    DatabaseError,
    DatabaseRequirements,
    TxId,
    TxShape,
  >(
    acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
    options: {
      readonly mapping: PasswordRegistrationMapping<
        NoInfer<Registration>,
        S,
        I,
        C,
        AC,
        Rq,
        NativeId
      >;
      readonly target: SuppliedService<TargetId, PasswordRegistrationAuthority<Registration>>;
      readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<Database>>, TxShape>;
    },
    body: Effect.Effect<Out, E, R>,
  ): Effect.Effect<
    Out,
    E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
    Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
  > {
    return Effect.flatMap(acquire, (database) =>
      coordinateSqlitePasswordRegistration(
        database,
        options.mapping,
        configurationFor(database),
        (
          transaction: TransactionOf<Database>,
          services: { readonly registrationAuthority: PasswordRegistrationAuthority<Registration> },
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
    makePasswordPersistenceServices: <
      S extends AnySQLiteTable,
      I extends AnySQLiteTable,
      C extends AnySQLiteTable,
      AC extends AnySQLiteTable,
      A extends AnySQLiteTable,
      RS extends AnySQLiteTable,
      CE extends AnySQLiteTable,
      M extends AnySQLiteTable,
      NativeId,
    >(
      database: D,
      mapping: Mapping<S, I, C, AC, A, RS, CE, M, NativeId>,
      proofMapping?: ProofPersistenceMapping<
        any,
        any,
        any,
        any,
        any,
        any,
        any,
        any,
        any,
        any,
        any,
        any
      >,
    ) =>
      makeSqlitePasswordPersistenceServices(
        database,
        mapping,
        configurationFor(database),
        proofMapping,
      ),
    coordinatePasswordPersistence,
    makePasswordRegistrationServices: <
      Registration,
      S extends AnySQLiteTable,
      I extends AnySQLiteTable,
      C extends AnySQLiteTable,
      AC extends AnySQLiteTable,
      Rq extends AnySQLiteTable,
      NativeId,
    >(
      database: D,
      mapping: PasswordRegistrationMapping<Registration, S, I, C, AC, Rq, NativeId>,
    ) => makeSqlitePasswordRegistrationServices(database, mapping, configurationFor(database)),
    coordinatePasswordRegistration,
  };
};
