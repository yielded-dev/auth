import {
  coordinateCommit,
  hasCommitScope,
  type LifecycleHooks,
  type HookConfigurationError,
} from "@yielded/auth/Hooks";
import {
  AuthenticationAuthority,
  SessionUnavailable,
  type PendingAuthentication,
  type SessionRepository,
  type SignedSessionValidity,
  type StatefulSessionPersistence,
  type SessionStepUpPersistence,
} from "@yielded/auth/Sessions";
/* oxlint-disable no-explicit-any -- target entrypoints restore each concrete Drizzle database/table type. */
import { type Context, Effect, Layer } from "effect";
import type * as SqlError from "effect/unstable/sql/SqlError";

import {
  makeSqlAuthenticationAuthority,
  makeSqlPendingAuthentication,
  makeSqlSignedValidity,
  makeSqlStatefulSessions,
  makeSqlSessionStepUp,
  CurrentSessionSql,
  type SessionSqlDatabase,
  type SessionSqlOptions,
} from "./session-sql";
import { sqlClientStandaloneGuard } from "./standalone-guard";

export interface SessionTargetConfiguration {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly standaloneGuard: Effect.Effect<void, SessionUnavailable>;
  readonly coordinatorGuard?: Effect.Effect<void, SessionUnavailable>;
}

interface TransactionOwner<Transaction> {
  readonly transaction: <A, E, R>(
    body: (transaction: Transaction) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | SqlError.SqlError, R>;
}

type CoordinatorError<E> = E | SessionUnavailable | HookConfigurationError | SqlError.SqlError;

export const sqlClientSessionStandaloneGuard = (
  database: unknown,
): Effect.Effect<void, SessionUnavailable> =>
  sqlClientStandaloneGuard(database, () => SessionUnavailable.make({}));

const options = (
  configuration: SessionTargetConfiguration,
  transactionBound = false,
): SessionSqlOptions => ({
  mode: configuration.mode,
  locking: configuration.locking,
  standaloneGuard: transactionBound ? Effect.void : configuration.standaloneGuard,
});

export const makeTargetAuthenticationAuthorityServices = <Claims>(
  database: any,
  mapping: any,
  configuration: SessionTargetConfiguration,
) =>
  Effect.map(
    makeSqlAuthenticationAuthority<Claims>(database, mapping, options(configuration)),
    (authenticationAuthority) => ({ authenticationAuthority }),
  );

export const makeTargetPendingAuthenticationServices = <Claims>(
  database: any,
  mapping: any,
  configuration: SessionTargetConfiguration,
) =>
  Effect.map(
    makeSqlPendingAuthentication<Claims>(database, mapping, options(configuration)),
    (pendingAuthentication) => ({ pendingAuthentication }),
  );

export const makeTargetStatefulSessionServices = <Claims>(
  database: any,
  mapping: any,
  configuration: SessionTargetConfiguration,
) => makeSqlStatefulSessions<Claims>(database, mapping, options(configuration));

export const makeTargetSignedSessionValidityServices = (
  database: any,
  mapping: any,
  configuration: SessionTargetConfiguration,
) =>
  Effect.map(
    makeSqlSignedValidity(database, mapping, options(configuration)),
    (signedSessionValidity) => ({
      signedSessionValidity,
    }),
  );

/**
 * The native transaction is the root commit owner. Interruption or owner
 * failure rolls it back and discards the child journal; this adapter performs
 * no hidden retry. A caller that can safely retry must rerun the complete owner
 * operation and prepare fresh bearer material. The low-level coordinator keeps
 * caller failures intact, including Drizzle query wrappers, and exposes a
 * native `SqlError` when transaction acquisition fails. Captured service
 * operations normalize their own driver failures to `SessionUnavailable`.
 */
const coordinate = <Transaction, Services, A, E, R>(
  database: TransactionOwner<Transaction>,
  configuration: SessionTargetConfiguration,
  make: (transaction: Transaction) => Effect.Effect<Services, never, LifecycleHooks>,
  owner: (transaction: Transaction, services: Services) => Effect.Effect<A, E, R>,
): Effect.Effect<A, CoordinatorError<E>, R | LifecycleHooks> =>
  Effect.gen(function* (): Effect.fn.Return<A, CoordinatorError<E>, R | LifecycleHooks> {
    if (yield* hasCommitScope) return yield* SessionUnavailable.make({});
    yield* configuration.coordinatorGuard ?? configuration.standaloneGuard;

    const result = yield* coordinateCommit(
      () =>
        database.transaction((transaction) =>
          Effect.gen(function* () {
            const services = yield* make(transaction);

            return yield* owner(transaction, services);
          }).pipe(
            Effect.provideService(CurrentSessionSql, transaction as unknown as SessionSqlDatabase),
          ),
        ),
      { mode: configuration.mode },
    );

    return result.value;
  });

export const coordinateTargetAuthenticationAuthority = <Claims, Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: { readonly authenticationAuthority: AuthenticationAuthority["Service"] },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinate(
    database,
    configuration,
    (transaction) =>
      Effect.map(
        makeSqlAuthenticationAuthority<Claims>(
          transaction as unknown as SessionSqlDatabase,
          mapping,
          options(configuration, true),
        ),
        (authenticationAuthority) => ({ authenticationAuthority }),
      ),
    owner,
  );

export const coordinateTargetPendingAuthentication = <Claims, Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: { readonly pendingAuthentication: PendingAuthentication<Claims> },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinate(
    database,
    configuration,
    (transaction) =>
      Effect.map(
        makeSqlPendingAuthentication<Claims>(
          transaction as unknown as SessionSqlDatabase,
          mapping,
          options(configuration, true),
        ),
        (pendingAuthentication) => ({ pendingAuthentication }),
      ),
    owner,
  );

export const coordinateTargetStatefulSessions = <Claims, Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: {
      readonly statefulSessionPersistence: StatefulSessionPersistence<Claims>;
      readonly sessionRepository: SessionRepository;
    },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinate(
    database,
    configuration,
    (transaction) =>
      makeSqlStatefulSessions<Claims>(
        transaction as unknown as SessionSqlDatabase,
        mapping,
        options(configuration, true),
      ),
    owner,
  );

export const coordinateTargetSignedSessionValidity = <Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: { readonly signedSessionValidity: SignedSessionValidity },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinate(
    database,
    configuration,
    (transaction) =>
      Effect.map(
        makeSqlSignedValidity(
          transaction as unknown as SessionSqlDatabase,
          mapping,
          options(configuration, true),
        ),
        (signedSessionValidity) => ({ signedSessionValidity }),
      ),
    owner,
  );

export const authenticationAuthorityLayer = (
  services: Effect.Effect<
    {
      readonly authenticationAuthority: AuthenticationAuthority["Service"];
    },
    never,
    LifecycleHooks
  >,
) =>
  Layer.effect(
    AuthenticationAuthority,
    Effect.map(services, (value) => value.authenticationAuthority),
  );

export const statefulSessionLayers = <Claims>(
  module: {
    readonly StatefulSessionPersistence: any;
    readonly SessionRepository: any;
  },
  services: Effect.Effect<
    {
      readonly statefulSessionPersistence: StatefulSessionPersistence<Claims>;
      readonly sessionRepository: SessionRepository;
    },
    never,
    LifecycleHooks
  >,
) =>
  Layer.merge(
    Layer.effect(
      module.StatefulSessionPersistence,
      Effect.map(services, (value) => value.statefulSessionPersistence),
    ),
    Layer.effect(
      module.SessionRepository,
      Effect.map(services, (value) => value.sessionRepository),
    ),
  );

export const pendingAuthenticationLayer = <Claims>(
  module: { readonly PendingAuthentication: any },
  services: Effect.Effect<
    {
      readonly pendingAuthentication: PendingAuthentication<Claims>;
    },
    never,
    LifecycleHooks
  >,
) =>
  Layer.effect(
    module.PendingAuthentication,
    Effect.map(services, (value) => value.pendingAuthentication),
  );

export const signedSessionValidityLayer = (
  module: { readonly SignedSessionValidity: any },
  services: Effect.Effect<
    {
      readonly signedSessionValidity: SignedSessionValidity;
    },
    never,
    LifecycleHooks
  >,
) =>
  Layer.effect(
    module.SignedSessionValidity,
    Effect.map(services, (value) => value.signedSessionValidity),
  );

export const makeTargetSessionStepUpServices = <Claims, Id>(
  database: any,
  mapping: any,
  target: Context.Service<Id, SessionStepUpPersistence<Claims>>,
  configuration: SessionTargetConfiguration,
) =>
  Effect.map(
    makeSqlSessionStepUp<Claims>(database, mapping, options(configuration)),
    (sessionStepUpPersistence) => ({
      sessionStepUpPersistence: target.of(sessionStepUpPersistence),
    }),
  );

export const coordinateTargetSessionStepUp = <Claims, Id, Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  target: Context.Service<Id, SessionStepUpPersistence<Claims>>,
  configuration: SessionTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: { readonly sessionStepUpPersistence: SessionStepUpPersistence<Claims> },
  ) => Effect.Effect<A, E, R>,
) =>
  coordinate(
    database,
    configuration,
    (transaction) =>
      Effect.map(
        makeSqlSessionStepUp<Claims>(
          transaction as unknown as SessionSqlDatabase,
          mapping,
          options(configuration, true),
        ),
        (sessionStepUpPersistence) => ({
          sessionStepUpPersistence: target.of(sessionStepUpPersistence),
        }),
      ),
    owner,
  );
