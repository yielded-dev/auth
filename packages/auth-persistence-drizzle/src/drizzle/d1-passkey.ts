import type { D1Client } from "@effect/sql-d1/D1Client";
import type { LifecycleHooks } from "@yielded/auth/Hooks";
import { PasskeyPersistence, PasskeyManagementPersistence } from "@yielded/auth/Passkey";
import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteD1Database } from "drizzle-orm/effect-d1";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { type Crypto, Effect, Context } from "effect";

import { Database as DatabaseService } from "./d1-database";
import { D1BatchStatements } from "./D1BatchStatements";
import { NativeDatabase, nativeDatabase } from "./native-database";
import { makePasskeyTarget } from "./passkey-drivers";
import type {
  D1PasskeyMapping,
  PasskeyCredentialMapping,
  PasskeyMappingSource,
  PasskeyPersistenceMapping,
} from "./passkey-model";
import type { PasskeyRegistrationCeremonyMapping } from "./passkey-registration-ceremony-model";
import {
  type PasskeyCoordinatorError,
  coordinateTargetPasskey,
  coordinateTargetPasskeyRegistration,
} from "./passkey/target";

type Table = AnySQLiteTable<{ dialect: "sqlite" }>;
type Database = EffectSQLiteD1Database<AnyRelations> & { readonly $client: D1Client };

const configuration = {
  mode: "batch" as const,
  dialect: "sqlite" as const,
  locking: false,
  standaloneGuard: () => Effect.void,
};

const target = makePasskeyTarget<DatabaseService, Database, Table, D1PasskeyMapping>(
  DatabaseService,
  configuration,
);

export const {
  makePasskeyCredentialServices,
  makePasskeyPersistenceServices,
  makePasskeyRegistrationCeremonyServices,
  makePasskeyManagementServices,
  makePasskeyRegistrationServices,
} = target;

export function coordinatePasskeyPersistence<
  D extends Database,
  S extends Table,
  C extends Table,
  F extends Table,
  Flow extends Table,
  N,
  A,
  E,
  R,
  RSetup = never,
  DatabaseError = never,
  DatabaseRequirements = never,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasskeyMappingSource<
      PasskeyPersistenceMapping<PasskeyCredentialMapping<S, C, F, N>, Flow, N> & D1PasskeyMapping,
      RSetup
    >;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  PasskeyCoordinatorError<E> | DatabaseError,
  | Exclude<R, PasskeyPersistence | D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
  | RSetup
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetPasskey(database, options.mapping, configuration, (_, services) =>
      Effect.flatMap(D1BatchStatements, (collector) =>
        Effect.provideContext(
          body,
          Context.make(PasskeyPersistence, services.passkeyPersistence).pipe(
            Context.add(D1BatchStatements, collector),
          ),
        ),
      ),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

export function coordinatePasskeyRegistrationCeremony<
  D extends Database,
  Flow extends Table,
  A,
  E,
  R,
  RSetup = never,
  DatabaseError = never,
  DatabaseRequirements = never,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasskeyMappingSource<
      PasskeyRegistrationCeremonyMapping<Flow> & D1PasskeyMapping,
      RSetup
    >;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  PasskeyCoordinatorError<E> | DatabaseError,
  | Exclude<R, PasskeyPersistence | D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
  | RSetup
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetPasskeyRegistration(database, options.mapping, configuration, (_, services) =>
      Effect.flatMap(D1BatchStatements, (collector) =>
        Effect.provideContext(
          body,
          Context.make(PasskeyPersistence, services.passkeyPersistence).pipe(
            Context.add(D1BatchStatements, collector),
          ),
        ),
      ),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

import type {
  PasskeyManagementMapping,
  PasskeyRegistrationMapping,
  PasskeyRegistrationServices,
  PasskeyRegistrationWriter,
} from "./passkey-write-model";
import {
  coordinateTargetPasskeyManagement,
  coordinateTargetPasskeyRegistrationWriter,
} from "./passkey/write-target";

export function coordinatePasskeyManagement<
  D extends Database,
  S extends Table,
  C extends Table,
  F extends Table,
  Flow extends Table,
  N,
  A,
  E,
  R,
  RSetup = never,
  DatabaseError = never,
  DatabaseRequirements = never,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasskeyMappingSource<
      PasskeyManagementMapping<S, C, F, Flow, N> & D1PasskeyMapping,
      RSetup
    >;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  PasskeyCoordinatorError<E> | DatabaseError,
  | Exclude<R, PasskeyPersistence | PasskeyManagementPersistence | D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
  | RSetup
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetPasskeyManagement(database, options.mapping, configuration, (_, services) =>
      Effect.flatMap(D1BatchStatements, (collector) =>
        Effect.provideContext(
          body,
          Context.make(PasskeyPersistence, services.passkeyPersistence)
            .pipe(Context.add(PasskeyManagementPersistence, services.passkeyManagementPersistence))
            .pipe(Context.add(D1BatchStatements, collector)),
        ),
      ),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}

export function coordinatePasskeyRegistration<
  D extends Database,
  S extends Table,
  C extends Table,
  F extends Table,
  Flow extends Table,
  N,
  Value,
  AuthorityId,
  A,
  E,
  R,
  RSetup = never,
  DatabaseError = never,
  DatabaseRequirements = never,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: PasskeyMappingSource<
      PasskeyRegistrationMapping<S, C, F, Flow, N, Value> & D1PasskeyMapping,
      RSetup
    >;
    readonly authority: Context.Key<AuthorityId, PasskeyRegistrationWriter<Value>>;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  PasskeyCoordinatorError<E> | DatabaseError,
  | Exclude<R, PasskeyPersistence | AuthorityId | D1BatchStatements>
  | Crypto.Crypto
  | LifecycleHooks
  | DatabaseRequirements
  | RSetup
> {
  return Effect.flatMap(nativeDatabase(acquire), (database) =>
    coordinateTargetPasskeyRegistrationWriter(
      database,
      options.mapping,
      configuration,
      (_, services: PasskeyRegistrationServices<Value>) =>
        Effect.flatMap(D1BatchStatements, (collector) =>
          Effect.provideContext(
            body,
            Context.make(PasskeyPersistence, services.passkeyPersistence)
              .pipe(Context.add(options.authority, services.passkeyRegistrationAuthority))
              .pipe(Context.add(D1BatchStatements, collector)),
          ),
        ),
    ).pipe(Effect.provideService(NativeDatabase, database)),
  );
}
