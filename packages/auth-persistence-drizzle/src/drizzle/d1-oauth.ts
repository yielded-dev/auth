import type { D1Client } from "@effect/sql-d1/D1Client";
import type { LifecycleHooks } from "@yielded/auth/Hooks";
import type { OAuthUnavailable } from "@yielded/auth/OAuth";
import {
  OAuthAccountsPersistence,
  OAuthRegistrationIntents,
  OAuthSignInPersistence,
} from "@yielded/auth/OAuth";
import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteD1Database } from "drizzle-orm/effect-d1";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { type Crypto, Effect } from "effect";

import { Database as DatabaseService } from "./d1-database";
import type { D1BatchStatements } from "./D1BatchStatements";
import { NativeDatabase, nativeDatabase } from "./native-database";
import type {
  OAuthAccountsMapping,
  OAuthD1Mapping,
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
} from "./oauth-target";
import type { SuppliedService } from "./SuppliedService";
type SQLiteTable = AnySQLiteTable<{ dialect: "sqlite" }>;
type Database = EffectSQLiteD1Database<AnyRelations> & { readonly $client: D1Client };

const configuration = {
  mode: "batch" as const,
  dialect: "sqlite" as const,
  locking: false,
  standaloneGuard: () => Effect.void,
};

export const makeD1OAuthAccountsServices = <
  S extends SQLiteTable,
  O extends SQLiteTable,
  C extends SQLiteTable,
  AC extends SQLiteTable,
  F extends SQLiteTable,
  N,
>(
  mapping: OAuthAccountsMapping<S, O, C, AC, F, N> & OAuthD1Mapping,
) =>
  makeTargetOAuthAccountsServices(mapping, configuration).pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(DatabaseService)),
  );

export const makeD1OAuthSignInServices = <
  S extends SQLiteTable,
  O extends SQLiteTable,
  C extends SQLiteTable,
  AC extends SQLiteTable,
  F extends SQLiteTable,
  N,
>(
  mapping: OAuthSignInMapping<S, O, C, AC, F, N> & OAuthD1Mapping,
) =>
  makeTargetOAuthSignInServices(mapping, configuration).pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(DatabaseService)),
  );

export const makeD1OAuthRegistrationIntentServices = <
  O extends SQLiteTable,
  I extends SQLiteTable,
  N,
>(
  mapping: OAuthRegistrationIntentMapping<O, I, N> & OAuthD1Mapping,
) =>
  makeTargetOAuthRegistrationIntentServices(mapping, configuration).pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(DatabaseService)),
  );

export const makeD1OAuthRegistrationServices = <
  Registration,
  S extends SQLiteTable,
  O extends SQLiteTable,
  C extends SQLiteTable,
  AC extends SQLiteTable,
  I extends SQLiteTable,
  N,
>(
  mapping: OAuthRegistrationMapping<Registration, S, O, C, AC, I, N> & OAuthD1Mapping,
) =>
  makeTargetOAuthRegistrationServices<Registration>(mapping, configuration).pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(DatabaseService)),
  );

export function coordinateD1OAuthSignIn<
  S extends SQLiteTable,
  O extends SQLiteTable,
  C extends SQLiteTable,
  AC extends SQLiteTable,
  F extends SQLiteTable,
  N,
  A,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: OAuthSignInMapping<S, O, C, AC, F, N> & OAuthD1Mapping },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | DatabaseError,
  | Exclude<Exclude<R, OAuthSignInPersistence>, D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetOAuthSignIn<never, A, E | OAuthUnavailable, Exclude<R, OAuthSignInPersistence>>(
      database,
      options.mapping,
      configuration,
      (_transaction, services) =>
        Effect.provideService(body, OAuthSignInPersistence, services.oauthSignInPersistence),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

export function coordinateD1OAuthRegistrationIntents<
  O extends SQLiteTable,
  I extends SQLiteTable,
  N,
  A,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: OAuthRegistrationIntentMapping<O, I, N> & OAuthD1Mapping;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | DatabaseError,
  | Exclude<Exclude<R, OAuthRegistrationIntents>, D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetOAuthRegistrationIntents<
      never,
      A,
      E | OAuthUnavailable,
      Exclude<R, OAuthRegistrationIntents>
    >(database, options.mapping, configuration, (_transaction, services) =>
      Effect.provideService(body, OAuthRegistrationIntents, services.oauthRegistrationIntents),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

export function coordinateD1OAuthAccounts<
  S extends SQLiteTable,
  O extends SQLiteTable,
  C extends SQLiteTable,
  AC extends SQLiteTable,
  F extends SQLiteTable,
  N,
  A,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: OAuthAccountsMapping<S, O, C, AC, F, N> & OAuthD1Mapping },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | DatabaseError,
  | Exclude<Exclude<R, OAuthAccountsPersistence>, D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetOAuthAccounts<
      never,
      A,
      E | OAuthUnavailable,
      Exclude<R, OAuthAccountsPersistence>
    >(database, options.mapping, configuration, (_transaction, services) =>
      Effect.provideService(body, OAuthAccountsPersistence, services.oauthAccountsPersistence),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

export function coordinateD1OAuthRegistration<
  TargetId,
  Registration,
  S extends SQLiteTable,
  O extends SQLiteTable,
  C extends SQLiteTable,
  AC extends SQLiteTable,
  I extends SQLiteTable,
  N,
  A,
  E,
  R,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<Database, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: OAuthRegistrationMapping<NoInfer<Registration>, S, O, C, AC, I, N> &
      OAuthD1Mapping;
    readonly target: SuppliedService<TargetId, OAuthRegistrationAuthority<Registration>>;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | DatabaseError,
  | Exclude<Exclude<R, TargetId>, D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetOAuthRegistration<
      Registration,
      never,
      A,
      E | OAuthUnavailable,
      Exclude<R, TargetId>
    >(database, options.mapping, configuration, (_transaction, services) =>
      Effect.provideService(body, options.target, services.registrationAuthority),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}
