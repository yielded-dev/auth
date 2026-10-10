/** Direct PostgreSQL and SQLite owners for upstream OAuth. Provider exchange stays outside these transactions. */
import { hasCommitScope, type LifecycleHooks } from "@yielded/auth/Hooks";
import {
  OAuthAccountsPersistence,
  OAuthSignInPersistence,
  OAuthRegistrationIntents,
  OAuthConnectedPersistence,
  OAuthConnectedRevocations,
  OAuthUnavailable,
} from "@yielded/auth/OAuth";
import { reportAuthDiagnostic } from "@yielded/auth/Persistence";
import { type Context, type Crypto, Effect, Predicate, Schema } from "effect";
import { SqlClient } from "effect/sql";

import { PersistenceConfigurationError } from "./internal/configuration";
import { makeNativeSqlTables } from "./internal/native-sql-table";
import {
  makeNativeOAuthAccountsServices,
  type OAuthNativeAccountsMapping,
} from "./internal/oauth/native-accounts";
import { makeNativeOAuthConnectedServices } from "./internal/oauth/native-connected";
import type { OAuthNativeConnectedMapping } from "./internal/oauth/native-connected-state";
import {
  makeNativeOAuthRegistrationIntentServices,
  makeNativeOAuthRegistrationServices,
  type OAuthNativeRegistrationIntentMapping,
  type OAuthNativeRegistrationMapping,
} from "./internal/oauth/native-registration";
import {
  makeNativeOAuthRevocationServices,
  type OAuthNativeRevocationMapping,
} from "./internal/oauth/native-revocations";
import { makeNativeOAuthSignInServices } from "./internal/oauth/native-sign-in";
import { type OAuthNativeReadMapping } from "./internal/oauth/native-state";
import { captureOAuthMapping } from "./internal/oauth/state";
import { makeSqlCommitExecutor } from "./internal/sql-commit";
import { sql, SqlExpression } from "./internal/sql-expression";
import type {
  OAuthConnectedMapping,
  OAuthConnectedRevocationMapping,
} from "./internal/sql-oauth-connected-model";
import type {
  OAuthAccountsMapping,
  OAuthSignInMapping,
  OAuthRegistrationIntentMapping,
  OAuthRegistrationMapping,
  OAuthRegistrationAuthority,
} from "./internal/sql-oauth-model";
import { validateSqlStorage } from "./internal/sql-storage-validation";
import { Table } from "./internal/sql-table";
import { requireStandalone } from "./internal/standalone";
import type { StorageTable } from "./internal/storage-tables";
import { withStorageValidation } from "./internal/storage-validation";
export * from "./internal/sql-oauth-model";
export * from "./internal/sql-oauth-connected-model";
export * from "./internal/oauth/native-layers";
export { sql, and, eq } from "./internal/sql-expression";
export { makeAuthenticationAuthorityServices } from "./internal/sql-authority";

export const table = (definition: StorageTable) =>
  new Table(definition.name, definition.columns, definition.unique, definition.schema);

export const clock = {
  encodeInstant: Schema.encodeSync(Schema.Int),
  decodeInstant: Schema.decodeUnknownSync(Schema.Int),
  engineNowMillis: new SqlExpression((client) =>
    client.onDialectOrElse({
      pg: () => client`cast(extract(epoch from clock_timestamp()) * 1000 as bigint)`,
      orElse: () => client`cast(round((julianday('now') - 2440587.5) * 86400000) as integer)`,
    }),
  ),
  toMillis: (expression: SqlExpression) => expression,
  fromMillis: (expression: SqlExpression) => expression,
};

const acquire = Effect.gen(function* () {
  const client = yield* SqlClient.SqlClient;

  if (
    !client.onDialectOrElse({ pg: () => true, sqlite: () => true, orElse: () => false }) ||
    Predicate.hasProperty(client, "~@effect/sql-d1/D1Client")
  ) {
    yield* reportAuthDiagnostic("persistence-validation", "configuration");

    return yield* PersistenceConfigurationError.make({
      reason: "OAuth persistence requires PostgreSQL or SQLite with interactive transactions",
    });
  }

  return { client, tables: makeNativeSqlTables(client) };
});

const using = <M, A, E, R>(
  original: M,
  make: (tables: ReturnType<typeof makeNativeSqlTables>, mapping: M) => Effect.Effect<A, E, R>,
) =>
  Effect.gen(function* () {
    const target = yield* acquire;
    const mapping = captureOAuthMapping(original);

    yield* validateSqlStorage(mapping).pipe(Effect.mapError(() => OAuthUnavailable.make({})));

    return yield* make(target.tables, mapping);
  }).pipe(withStorageValidation);

const coordinate = <S, A, E, R, ES, RS>(
  make: Effect.Effect<S, ES, RS>,
  body: (services: S) => Effect.Effect<A, E, R>,
) =>
  Effect.gen(function* () {
    const { client } = yield* acquire;

    if (yield* hasCommitScope) return yield* OAuthUnavailable.make({});
    yield* requireStandalone(() => OAuthUnavailable.make({}), client.transactionService);
    const executor = yield* makeSqlCommitExecutor(() => OAuthUnavailable.make({}));

    return yield* executor.coordinate(
      Effect.flatMap(make.pipe(Effect.mapError(() => OAuthUnavailable.make({}))), body),
    );
  });

export const makeOAuthSignInServices = <N>(
  mapping: OAuthSignInMapping<Table, Table, Table, Table, Table, N>,
): Effect.Effect<
  { readonly oauthSignInPersistence: OAuthSignInPersistence["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(mapping, (tables, value) =>
    makeNativeOAuthSignInServices(tables, value as unknown as OAuthNativeReadMapping),
  );

export const coordinateOAuthSignIn = <N, A, E, R>(
  options: { readonly mapping: OAuthSignInMapping<Table, Table, Table, Table, Table, N> },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  E | OAuthUnavailable | PersistenceConfigurationError,
  Exclude<R, OAuthSignInPersistence> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  coordinate(makeOAuthSignInServices(options.mapping), (services) =>
    Effect.provideService(body, OAuthSignInPersistence, services.oauthSignInPersistence),
  );

export const makeOAuthAccountsServices = <N>(
  mapping: OAuthAccountsMapping<Table, Table, Table, Table, Table, N>,
): Effect.Effect<
  { readonly oauthAccountsPersistence: OAuthAccountsPersistence["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(mapping, (tables, value) =>
    makeNativeOAuthAccountsServices(tables, value as unknown as OAuthNativeAccountsMapping),
  );

export const coordinateOAuthAccounts = <N, A, E, R>(
  options: { readonly mapping: OAuthAccountsMapping<Table, Table, Table, Table, Table, N> },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  E | OAuthUnavailable | PersistenceConfigurationError,
  Exclude<R, OAuthAccountsPersistence> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  coordinate(makeOAuthAccountsServices(options.mapping), (services) =>
    Effect.provideService(body, OAuthAccountsPersistence, services.oauthAccountsPersistence),
  );

export const makeOAuthRegistrationIntentServices = <N>(
  mapping: OAuthRegistrationIntentMapping<Table, Table, N>,
): Effect.Effect<
  { readonly oauthRegistrationIntents: OAuthRegistrationIntents["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(mapping, (tables, value) =>
    makeNativeOAuthRegistrationIntentServices(
      tables,
      value as unknown as OAuthNativeRegistrationIntentMapping,
    ),
  );

export const coordinateOAuthRegistrationIntents = <N, A, E, R>(
  options: { readonly mapping: OAuthRegistrationIntentMapping<Table, Table, N> },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  E | OAuthUnavailable | PersistenceConfigurationError,
  Exclude<R, OAuthRegistrationIntents> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  coordinate(makeOAuthRegistrationIntentServices(options.mapping), (services) =>
    Effect.provideService(body, OAuthRegistrationIntents, services.oauthRegistrationIntents),
  );

export const makeOAuthConnectedServices = <N>(
  mapping: OAuthConnectedMapping<Table, Table, Table, Table, Table, N, Table>,
): Effect.Effect<
  { readonly oauthConnectedPersistence: OAuthConnectedPersistence["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(mapping, (tables, value) =>
    makeNativeOAuthConnectedServices(tables, value as unknown as OAuthNativeConnectedMapping),
  );

export const coordinateOAuthConnected = <N, A, E, R>(
  options: { readonly mapping: OAuthConnectedMapping<Table, Table, Table, Table, Table, N, Table> },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  E | OAuthUnavailable | PersistenceConfigurationError,
  Exclude<R, OAuthConnectedPersistence> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  coordinate(makeOAuthConnectedServices(options.mapping), (services) =>
    Effect.provideService(body, OAuthConnectedPersistence, services.oauthConnectedPersistence),
  );

export const makeOAuthConnectedRevocationServices = <N>(
  mapping: OAuthConnectedRevocationMapping<Table, Table, Table, N>,
): Effect.Effect<
  { readonly oauthConnectedRevocations: OAuthConnectedRevocations["Service"] },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(mapping, (tables, value) =>
    makeNativeOAuthRevocationServices(tables, value as unknown as OAuthNativeRevocationMapping),
  );

export const coordinateOAuthConnectedRevocations = <N, A, E, R>(
  options: { readonly mapping: OAuthConnectedRevocationMapping<Table, Table, Table, N> },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  E | OAuthUnavailable | PersistenceConfigurationError,
  Exclude<R, OAuthConnectedRevocations> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  coordinate(makeOAuthConnectedRevocationServices(options.mapping), (services) =>
    Effect.provideService(body, OAuthConnectedRevocations, services.oauthConnectedRevocations),
  );

export const makeOAuthRegistrationServices = <Registration, N>(
  mapping: OAuthRegistrationMapping<Registration, Table, Table, Table, Table, Table, N>,
): Effect.Effect<
  { readonly registrationAuthority: OAuthRegistrationAuthority<Registration> },
  OAuthUnavailable | PersistenceConfigurationError,
  Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  using(mapping, (tables, value) =>
    makeNativeOAuthRegistrationServices(
      tables,
      value as unknown as OAuthNativeRegistrationMapping<Registration>,
    ),
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
      N
    >;
    readonly target: Context.Key<Id, OAuthRegistrationAuthority<Registration>>;
  },
  body: Effect.Effect<A, E, R>,
): Effect.Effect<
  A,
  E | OAuthUnavailable | PersistenceConfigurationError,
  Exclude<R, Id> | Crypto.Crypto | LifecycleHooks | SqlClient.SqlClient
> =>
  coordinate(makeOAuthRegistrationServices(options.mapping), (services) =>
    Effect.provideService(body, options.target, services.registrationAuthority),
  );

export const oauthConnectedOwnershipReferences = <N>(
  mapping: OAuthConnectedMapping<Table, Table, Table, Table, Table, N, Table>,
) => ({
  connectedReference: (input: { readonly identityKey: string; readonly subjectId: N }) => {
    const g = mapping.grant;
    const grant = sql`exists(select 1 from ${g.table} where ${g.table.columns[g.identityKey]} = ${input.identityKey} and ${g.table.columns[g.subjectId]} = ${input.subjectId})`;

    if (mapping.revocation.mode === "unsupported") return grant;
    const j = mapping.revocation.job;

    return sql`(${grant}) or exists(select 1 from ${j.table} where ${j.table.columns[j.identityKey]} = ${input.identityKey} and ${j.table.columns[j.subjectId]} = ${input.subjectId})`;
  },
});
