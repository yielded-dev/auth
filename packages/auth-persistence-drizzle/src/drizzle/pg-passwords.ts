import type { LifecycleHooks, HookConfigurationError } from "@yielded/auth/Hooks";
import { type PasswordUnavailable, PasswordPersistence } from "@yielded/auth/Password";
/* oxlint-disable no-explicit-any -- proof mapping tables are independently typed by the proof owner; this driver forwards them unchanged to the shared target. */
import type { AnyRelations } from "drizzle-orm";
import type { EffectPgDatabase as PgliteDatabase } from "drizzle-orm/effect-pglite";
import type { EffectPgDatabase as PostgresDatabase } from "drizzle-orm/effect-postgres";
import type { AnyPgTable } from "drizzle-orm/pg-core";
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
  sqlClientPasswordStandaloneGuard,
} from "./password-target";
import type { ProofPersistenceMapping } from "./proof-model";
import type { ProofSqlQuery } from "./proof-sql";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import type { SuppliedService } from "./SuppliedService";

type Database = PostgresDatabase<AnyRelations> | PgliteDatabase<AnyRelations>;
type TransactionOf<D extends Database> = Parameters<Parameters<D["transaction"]>[0]>[0];

const configuration = (database: Database) => ({
  mode: "interactive" as const,
  locking: true,
  standaloneGuard: sqlClientPasswordStandaloneGuard(database),
  insertIfAbsent: (query: PasswordSqlQuery) => query.onConflictDoNothing(),
  generatedSubjectRows: (query: PasswordSqlQuery) => query.returning(),
  proof: {
    mode: "interactive" as const,
    locking: true,
    standaloneGuard: sqlClientProofStandaloneGuard(database),
    insertIfAbsent: (query: ProofSqlQuery) => query.onConflictDoNothing(),
  },
});

type PasswordMapping<
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  A extends AnyPgTable,
  RS extends AnyPgTable,
  CE extends AnyPgTable,
  M extends AnyPgTable,
  NativeId,
> = PasswordPersistenceMapping<S, I, C, AC, A, RS, CE, M, NativeId>;

export const makePgPasswordPersistenceServices = <
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  A extends AnyPgTable,
  RS extends AnyPgTable,
  CE extends AnyPgTable,
  M extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: PasswordMapping<S, I, C, AC, A, RS, CE, M, NativeId>,
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
  makeTargetPasswordPersistenceServices(database, mapping, configuration(database), proofMapping);

export function coordinatePgPasswordPersistence<
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  A extends AnyPgTable,
  RS extends AnyPgTable,
  CE extends AnyPgTable,
  M extends AnyPgTable,
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
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasswordMapping<S, I, C, AC, A, RS, CE, M, NativeId>;
    readonly proofMapping?: PM;
    readonly transaction?: never;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, PasswordPersistence> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgPasswordPersistence<
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  A extends AnyPgTable,
  RS extends AnyPgTable,
  CE extends AnyPgTable,
  M extends AnyPgTable,
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
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasswordMapping<S, I, C, AC, A, RS, CE, M, NativeId>;
    readonly proofMapping?: PM;
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, PasswordPersistence | TxId> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgPasswordPersistence<
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  A extends AnyPgTable,
  RS extends AnyPgTable,
  CE extends AnyPgTable,
  M extends AnyPgTable,
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
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasswordMapping<S, I, C, AC, A, RS, CE, M, NativeId>;
    readonly proofMapping?: PM;
    readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, PasswordPersistence> | LifecycleHooks | DatabaseRequirements
> {
  return Effect.flatMap(acquire, (database) =>
    coordinateTargetPasswordPersistence<TransactionOf<D>, Out, E, Exclude<R, PasswordPersistence>>(
      database,
      options.mapping,
      configuration(database),
      options.proofMapping,
      (
        transaction: TransactionOf<D>,
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

export const makePgPasswordRegistrationServices = <
  Registration,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  Rq extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: PasswordRegistrationMapping<Registration, S, I, C, AC, Rq, NativeId>,
) =>
  makeTargetPasswordRegistrationServices<Registration>(database, mapping, configuration(database));

export function coordinatePgPasswordRegistration<
  TargetId,
  Registration,
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  Rq extends AnyPgTable,
  NativeId,
  Out,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasswordRegistrationMapping<NoInfer<Registration>, S, I, C, AC, Rq, NativeId>;
    readonly target: SuppliedService<TargetId, PasswordRegistrationAuthority<Registration>>;
    readonly transaction?: never;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgPasswordRegistration<
  TargetId,
  Registration,
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  Rq extends AnyPgTable,
  NativeId,
  Out,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasswordRegistrationMapping<NoInfer<Registration>, S, I, C, AC, Rq, NativeId>;
    readonly target: SuppliedService<TargetId, PasswordRegistrationAuthority<Registration>>;
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, TargetId | TxId> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgPasswordRegistration<
  TargetId,
  Registration,
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  Rq extends AnyPgTable,
  NativeId,
  Out,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasswordRegistrationMapping<NoInfer<Registration>, S, I, C, AC, Rq, NativeId>;
    readonly target: SuppliedService<TargetId, PasswordRegistrationAuthority<Registration>>;
    readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | PasswordUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
> {
  return Effect.flatMap(acquire, (database) =>
    coordinateTargetPasswordRegistration<
      Registration,
      TransactionOf<D>,
      Out,
      E,
      Exclude<R, TargetId>
    >(
      database,
      options.mapping,
      configuration(database),
      (
        transaction: TransactionOf<D>,
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

export { configuration as pgPasswordConfiguration };
