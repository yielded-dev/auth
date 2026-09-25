import { EmailAddressPersistence, type EmailUnavailable } from "@yielded/auth/Email";
import type { LifecycleHooks, HookConfigurationError } from "@yielded/auth/Hooks";
/* oxlint-disable no-explicit-any -- proof mapping tables are independently typed by the proof owner; this driver forwards them unchanged to the shared target. */
import type { AnyRelations } from "drizzle-orm";
import type { EffectPgDatabase as PgliteDatabase } from "drizzle-orm/effect-pglite";
import type { EffectPgDatabase as PostgresDatabase } from "drizzle-orm/effect-postgres";
import type { AnyPgTable } from "drizzle-orm/pg-core";
import { Effect, Context } from "effect";
import type { SqlError } from "effect/unstable/sql/SqlError";

import type {
  EmailAddressMapping,
  EmailRegistrationMapping,
  EmailSignInMapping,
} from "./email-model";
import type { EmailRegistrationAuthority } from "./email-registration";
import type { EmailSqlQuery } from "./email-sql";
import {
  coordinateTargetEmailAddress,
  coordinateTargetEmailRegistration,
  makeTargetEmailAddressServices,
  makeTargetEmailRegistrationServices,
  makeTargetEmailSignInServices,
  sqlClientEmailStandaloneGuard,
} from "./email-target";
import type { ProofPersistenceMapping } from "./proof-model";
import type { ProofSqlQuery } from "./proof-sql";
import { sqlClientProofStandaloneGuard } from "./proof-target";
import type { SuppliedService } from "./SuppliedService";

type Database = PostgresDatabase<AnyRelations> | PgliteDatabase<AnyRelations>;
type TransactionOf<D extends Database> = Parameters<Parameters<D["transaction"]>[0]>[0];
type ProofMapping = ProofPersistenceMapping<
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
>;

const configuration = (database: Database) => ({
  mode: "interactive" as const,
  locking: true,
  standaloneGuard: sqlClientEmailStandaloneGuard(database),
  generatedSubjectRows: (query: EmailSqlQuery) => query.returning(),
  proof: {
    mode: "interactive" as const,
    locking: true,
    standaloneGuard: sqlClientProofStandaloneGuard(database),
    insertIfAbsent: (query: ProofSqlQuery) => query.onConflictDoNothing(),
  },
});

export const makePgEmailSignInServices = <
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: EmailSignInMapping<S, I, C, NativeId>,
) => makeTargetEmailSignInServices(database, mapping, configuration(database));

export const makePgEmailAddressServices = <
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  M extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: EmailAddressMapping<S, I, C, AC, M, NativeId>,
  proofMapping: ProofMapping,
) => makeTargetEmailAddressServices(database, mapping, proofMapping, configuration(database));

export function coordinatePgEmailAddress<
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  M extends AnyPgTable,
  NativeId,
  Out,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: EmailAddressMapping<S, I, C, AC, M, NativeId>;
    readonly proofMapping: ProofMapping;
    readonly transaction?: never;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | EmailUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, EmailAddressPersistence> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgEmailAddress<
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  M extends AnyPgTable,
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
    readonly mapping: EmailAddressMapping<S, I, C, AC, M, NativeId>;
    readonly proofMapping: ProofMapping;
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | EmailUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, EmailAddressPersistence | TxId> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgEmailAddress<
  D extends Database,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  M extends AnyPgTable,
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
    readonly mapping: EmailAddressMapping<S, I, C, AC, M, NativeId>;
    readonly proofMapping: ProofMapping;
    readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | EmailUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, EmailAddressPersistence> | LifecycleHooks | DatabaseRequirements
> {
  return Effect.flatMap(acquire, (database) =>
    coordinateTargetEmailAddress<TransactionOf<D>, Out, E, Exclude<R, EmailAddressPersistence>>(
      database,
      options.mapping,
      options.proofMapping,
      configuration(database),
      (
        transaction: TransactionOf<D>,
        services: { readonly emailAddressPersistence: EmailAddressPersistence["Service"] },
      ) => {
        const provided = Context.make(EmailAddressPersistence, services.emailAddressPersistence);
        const work = Effect.provideContext(body, provided);

        return options.transaction === undefined
          ? work
          : Effect.provideService(work, options.transaction, options.transaction.of(transaction));
      },
    ),
  );
}

export const makePgEmailRegistrationServices = <
  Registration,
  S extends AnyPgTable,
  I extends AnyPgTable,
  C extends AnyPgTable,
  AC extends AnyPgTable,
  Rq extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: EmailRegistrationMapping<Registration, S, I, C, AC, Rq, NativeId>,
  proofMapping: ProofMapping,
) =>
  makeTargetEmailRegistrationServices<Registration>(
    database,
    mapping,
    proofMapping,
    configuration(database),
  );

export function coordinatePgEmailRegistration<
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
    readonly mapping: EmailRegistrationMapping<NoInfer<Registration>, S, I, C, AC, Rq, NativeId>;
    readonly proofMapping: ProofMapping;
    readonly target: SuppliedService<TargetId, EmailRegistrationAuthority<Registration>>;
    readonly transaction?: never;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | EmailUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgEmailRegistration<
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
    readonly mapping: EmailRegistrationMapping<NoInfer<Registration>, S, I, C, AC, Rq, NativeId>;
    readonly proofMapping: ProofMapping;
    readonly target: SuppliedService<TargetId, EmailRegistrationAuthority<Registration>>;
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | EmailUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, TargetId | TxId> | LifecycleHooks | DatabaseRequirements
>;

export function coordinatePgEmailRegistration<
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
    readonly mapping: EmailRegistrationMapping<NoInfer<Registration>, S, I, C, AC, Rq, NativeId>;
    readonly proofMapping: ProofMapping;
    readonly target: SuppliedService<TargetId, EmailRegistrationAuthority<Registration>>;
    readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<Out, E, R>,
): Effect.Effect<
  Out,
  E | EmailUnavailable | HookConfigurationError | SqlError | DatabaseError,
  Exclude<R, TargetId> | LifecycleHooks | DatabaseRequirements
> {
  return Effect.flatMap(acquire, (database) =>
    coordinateTargetEmailRegistration<Registration, TransactionOf<D>, Out, E, Exclude<R, TargetId>>(
      database,
      options.mapping,
      options.proofMapping,
      configuration(database),
      (
        transaction: TransactionOf<D>,
        services: { readonly registrationAuthority: EmailRegistrationAuthority<Registration> },
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
