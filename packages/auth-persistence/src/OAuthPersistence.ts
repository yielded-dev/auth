/** Direct Effect SQL persistence for upstream OAuth accounts. PostgreSQL and SQLite
 * require interactive transactions; provider exchanges occur outside coordinators. */
import type { LifecycleHooks } from "@yielded/auth/Hooks";
import {
  OAuthAccountsPersistence,
  OAuthSignInPersistence,
  OAuthRegistrationIntents,
  OAuthConnectedPersistence,
  OAuthConnectedRevocations,
  OAuthUnavailable,
} from "@yielded/auth/OAuth";
import type { AuthenticationAuthority } from "@yielded/auth/Sessions";
import { SessionUnavailable } from "@yielded/auth/Sessions";
import { type Context, type Crypto, Effect, Predicate, Schema } from "effect";
import { SqlClient } from "effect/sql";

import { PersistenceConfigurationError } from "./internal/configuration";
import type { AuthenticationAuthorityMapping as AuthorityMapping } from "./internal/models/session-model";
import { makeNativeSqlTables } from "./internal/native-sql-table";
import { makeOAuthKernel } from "./internal/oauth-kernel";
import type { OAuthCoordinatorError, OAuthTargetConfiguration } from "./internal/oauth/target";
import {
  CurrentSessionSql,
  makeSessionKernel,
  type SessionSqlDatabase,
} from "./internal/session-kernel";
import type {
  OAuthConnectedMapping,
  OAuthConnectedRevocationMapping,
} from "./internal/sql-oauth-connected-model";
import type {
  SqlTableModel,
  OAuthAccountsMapping,
  OAuthSignInMapping,
  OAuthRegistrationIntentMapping,
  OAuthRegistrationMapping,
  OAuthRegistrationAuthority,
  OAuthReferenceGuardDescriptor,
} from "./internal/sql-oauth-model";
import { makeSqlDatabase, sqlQueryOperations, sql } from "./internal/sql-query";
import { validateSqlStorage } from "./internal/sql-storage-validation";
import { Table, Fragment } from "./internal/sql-table";
import { requireStandalone } from "./internal/standalone";
import type { StorageTable } from "./internal/storage-tables";
import { NativeDatabase } from "./internal/transaction-kernel";
import type { TransactionNativeDatabase } from "./internal/transaction-kernel";
export * from "./internal/sql-oauth-model";
export * from "./internal/sql-oauth-connected-model";
export { sql };
export { and, eq } from "./internal/sql-query";

/** Physical identifiers and representations only; applications own migrations. */
export const table = (definition: StorageTable) =>
  new Table(definition.name, definition.columns, definition.unique, definition.schema);

/** Integer-millisecond engine clock, sampled after locks on either supported dialect. */
export const clock = {
  encodeInstant: Schema.encodeSync(Schema.Int),
  decodeInstant: Schema.decodeUnknownSync(Schema.Int),
  engineNowMillis: new Fragment((compiler) =>
    compiler.dialect === "pg"
      ? "cast(extract(epoch from clock_timestamp()) * 1000 as bigint)"
      : "cast(round((julianday('now') - 2440587.5) * 86400000) as integer)",
  ),
};

const operations = { ...sqlQueryOperations, validateStorage: validateSqlStorage };

const kernels = {
  pg: makeOAuthKernel(operations, () => "pg"),
  sqlite: makeOAuthKernel(operations, () => "sqlite"),
};

const acquire = Effect.gen(function* () {
  const client = yield* SqlClient.SqlClient;

  const dialect = client.onDialectOrElse({
    pg: () => "pg" as const,
    sqlite: () => "sqlite" as const,
    orElse: () => undefined,
  });

  // D1 exposes the SQLite compiler but its public driver brand identifies a
  // batch-only client. Keep the default package free of a D1 runtime dependency.
  if (dialect === undefined || Predicate.hasProperty(client, "~@effect/sql-d1/D1Client"))
    return yield* PersistenceConfigurationError.make({
      reason: "OAuth persistence requires PostgreSQL or SQLite with interactive transactions",
    });

  // Mapping expressions and projection aliases own their physical names. Retain
  // the client's connection/transaction identity while bypassing naming transforms.
  const database = yield* makeSqlDatabase(dialect).pipe(
    Effect.provideService(SqlClient.SqlClient, client.withoutTransforms()),
  );

  const configuration: OAuthTargetConfiguration = {
    mode: "interactive",
    dialect,
    locking: dialect === "pg",
    standaloneGuard: (service) => requireStandalone(() => OAuthUnavailable.make({}), service),
  };

  // Erase only the query-builder handle; batch methods are never selected by this adapter.
  return {
    database: database as unknown as TransactionNativeDatabase,
    configuration,
    kernel: kernels[dialect],
  };
});

const using = <A, E, R>(body: (input: Effect.Success<typeof acquire>) => Effect.Effect<A, E, R>) =>
  Effect.flatMap(acquire, (input) =>
    body(input).pipe(Effect.provideService(NativeDatabase, input.database)),
  );

export const makeOAuthSignInServices = <N>(
  mapping: OAuthSignInMapping<Table, Table, Table, Table, Table, N>,
): Effect.Effect<
  { readonly oauthSignInPersistence: OAuthSignInPersistence["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration }) =>
    kernel.target.makeTargetOAuthSignInServices(mapping, configuration),
  );

/** Run auth and application SQL in one adapter-owned transaction and commit journal. */
export const coordinateOAuthSignIn = <N, A, E, R>(
  options: { readonly mapping: OAuthSignInMapping<Table, Table, Table, Table, Table, N> },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | PersistenceConfigurationError,
  Exclude<R, OAuthSignInPersistence> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration, database }) =>
    kernel.target.coordinateTargetOAuthSignIn(
      database,
      options.mapping,
      configuration,
      (_transaction, services) =>
        Effect.provideService(body, OAuthSignInPersistence, services.oauthSignInPersistence),
    ),
  );

export const makeOAuthRegistrationIntentServices = <N>(
  mapping: OAuthRegistrationIntentMapping<Table, Table, Table, Table, Table, Table, Table, N>,
): Effect.Effect<
  { readonly oauthRegistrationIntents: OAuthRegistrationIntents["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration }) =>
    kernel.target.makeTargetOAuthRegistrationIntentServices(mapping, configuration),
  );

/** Run auth and application SQL in one adapter-owned transaction and commit journal. */
export const coordinateOAuthRegistrationIntents = <N, A, E, R>(
  options: {
    readonly mapping: OAuthRegistrationIntentMapping<
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      N
    >;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | PersistenceConfigurationError,
  Exclude<R, OAuthRegistrationIntents> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration, database }) =>
    kernel.target.coordinateTargetOAuthRegistrationIntents(
      database,
      options.mapping,
      configuration,
      (_transaction, services) =>
        Effect.provideService(body, OAuthRegistrationIntents, services.oauthRegistrationIntents),
    ),
  );

export const makeOAuthAccountsServices = <N>(
  mapping: OAuthAccountsMapping<Table, Table, Table, Table, Table, Table, Table, N>,
): Effect.Effect<
  { readonly oauthAccountsPersistence: OAuthAccountsPersistence["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration }) =>
    kernel.target.makeTargetOAuthAccountsServices(mapping, configuration),
  );

/** Run auth and application SQL in one adapter-owned transaction and commit journal. */
export const coordinateOAuthAccounts = <N, A, E, R>(
  options: {
    readonly mapping: OAuthAccountsMapping<Table, Table, Table, Table, Table, Table, Table, N>;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | PersistenceConfigurationError,
  Exclude<R, OAuthAccountsPersistence> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration, database }) =>
    kernel.target.coordinateTargetOAuthAccounts(
      database,
      options.mapping,
      configuration,
      (_transaction, services) =>
        Effect.provideService(body, OAuthAccountsPersistence, services.oauthAccountsPersistence),
    ),
  );

export const makeOAuthConnectedServices = <N>(
  mapping: OAuthConnectedMapping<
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    N,
    Table
  >,
): Effect.Effect<
  { readonly oauthConnectedPersistence: OAuthConnectedPersistence["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration }) =>
    kernel.connectedTarget.makeTargetOAuthConnectedServices(mapping, configuration),
  );

/** Run auth and application SQL in one adapter-owned transaction and commit journal. */
export const coordinateOAuthConnected = <N, A, E, R>(
  options: {
    readonly mapping: OAuthConnectedMapping<
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      N,
      Table
    >;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | PersistenceConfigurationError,
  Exclude<R, OAuthConnectedPersistence> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration, database }) =>
    kernel.connectedTarget.coordinateTargetOAuthConnected(
      database,
      options.mapping,
      configuration,
      (_transaction, services) =>
        Effect.provideService(body, OAuthConnectedPersistence, services.oauthConnectedPersistence),
    ),
  );

export const makeOAuthConnectedRevocationServices = <N>(
  mapping: OAuthConnectedRevocationMapping<Table, Table, Table, Table, Table, Table, Table, N>,
): Effect.Effect<
  { readonly oauthConnectedRevocations: OAuthConnectedRevocations["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration }) =>
    kernel.connectedTarget.makeTargetOAuthConnectedRevocationServices(mapping, configuration),
  );

/** Run auth and application SQL in one adapter-owned transaction and commit journal. */
export const coordinateOAuthConnectedRevocations = <N, A, E, R>(
  options: {
    readonly mapping: OAuthConnectedRevocationMapping<
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      N
    >;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | PersistenceConfigurationError,
  Exclude<R, OAuthConnectedRevocations> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration, database }) =>
    kernel.connectedTarget.coordinateTargetOAuthConnectedRevocations(
      database,
      options.mapping,
      configuration,
      (_transaction, services) =>
        Effect.provideService(body, OAuthConnectedRevocations, services.oauthConnectedRevocations),
    ),
  );

export const makeOAuthRegistrationServices = <Registration, N>(
  mapping: OAuthRegistrationMapping<
    Registration,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    N
  >,
): Effect.Effect<
  { readonly registrationAuthority: OAuthRegistrationAuthority<Registration> },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration }) =>
    kernel.target.makeTargetOAuthRegistrationServices<Registration>(mapping, configuration),
  );

export const coordinateOAuthRegistration = <Id, Registration, N, A, E, R>(
  options: {
    readonly mapping: OAuthRegistrationMapping<
      NoInfer<Registration>,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      Table,
      N
    >;
    readonly target: Context.Key<Id, OAuthRegistrationAuthority<Registration>>;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  OAuthCoordinatorError<E> | PersistenceConfigurationError,
  Exclude<R, Id> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ kernel, configuration, database }) =>
    kernel.target.coordinateTargetOAuthRegistration<Registration, unknown, A, E, Exclude<R, Id>>(
      database,
      options.mapping,
      configuration,
      (_transaction, services) =>
        Effect.provideService(body, options.target, services.registrationAuthority),
    ),
  );

/** Include these guards when login ownership may also hold retained grants. */
export const oauthConnectedOwnershipReferences = <N>(
  mapping: OAuthConnectedMapping<
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    Table,
    N,
    Table
  >,
  dialect: "pg" | "sqlite",
) =>
  // The selected compiler supplies Fragment handles; domain values retain their codecs.
  kernels[dialect].connectedReference.oauthConnectedOwnershipReferences(mapping) as {
    readonly connectedReferenceGuards: ReadonlyArray<OAuthReferenceGuardDescriptor<N>>;
    readonly connectedReference: (input: {
      readonly identityKey: string;
      readonly subjectId: N;
    }) => Fragment;
  };

export const {
  oauthAccountsPersistenceLayer,
  oauthSignInPersistenceLayer,
  oauthRegistrationIntentsLayer,
  oauthRegistrationAuthorityLayer,
} = kernels.sqlite.target;

export const { oauthConnectedPersistenceLayer, oauthConnectedRevocationsLayer } =
  kernels.sqlite.connectedTarget;

/** Shared session issuance must validate the same subject and credential authority
 * as OAuth. Supply this service when it is not already provided by session storage. */
export const makeAuthenticationAuthorityServices = <Claims, N>(
  mapping: AuthorityMapping<Claims, SqlTableModel, SqlTableModel, SqlTableModel, SqlTableModel, N>,
): Effect.Effect<
  { readonly authenticationAuthority: AuthenticationAuthority["Service"] },
  SessionUnavailable | PersistenceConfigurationError,
  LifecycleHooks | SqlClient.SqlClient
> =>
  using(({ database, configuration }) =>
    makeSessionKernel(operations, (client) => makeNativeSqlTables(client))
      .makeSqlAuthenticationAuthority(mapping, {
        mode: "interactive",
        locking: configuration.locking,
        standaloneGuard: requireStandalone(
          () => SessionUnavailable.make({}),
          database.$client.transactionService,
        ),
      })
      .pipe(
        // Both kernels capture the same raw SQL query-builder handle and client.
        Effect.provideService(CurrentSessionSql, database as unknown as SessionSqlDatabase),
        Effect.map((authenticationAuthority) => ({ authenticationAuthority })),
      ),
  );
