import {
  coordinateCommit,
  hasCommitScope,
  LifecycleHooks,
  type HookConfigurationError,
} from "@yielded/auth/Hooks";
import { PasswordUnavailable, PasswordPersistence } from "@yielded/auth/Password";
/* oxlint-disable no-explicit-any -- public driver wrappers restore concrete Drizzle generics. */
import { type Context, Effect, Layer } from "effect";
import type * as SqlError from "effect/unstable/sql/SqlError";

import {
  makeSqlPasswordRegistrationAuthority,
  type PasswordRegistrationAuthority,
  type PasswordRegistrationConfiguration,
} from "./password-registration";
import {
  makeSqlPasswordPersistence,
  type PasswordSqlConfiguration,
  type PasswordSqlDatabase,
  type PasswordSqlQuery,
} from "./password-sql";
import type { ProofTargetConfiguration } from "./proof-target";
import { sqlClientStandaloneGuard } from "./standalone-guard";

export interface PasswordTargetConfiguration {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly standaloneGuard: Effect.Effect<void, PasswordUnavailable>;
  readonly coordinatorGuard?: Effect.Effect<void, PasswordUnavailable>;
  readonly insertIfAbsent: (
    query: PasswordSqlQuery,
    selfKey: string,
    selfValue: unknown,
  ) => PasswordSqlQuery;
  readonly generatedSubjectRows: (query: PasswordSqlQuery) => PasswordSqlQuery;
  readonly proof: ProofTargetConfiguration;
}

interface TransactionOwner<Transaction> {
  readonly transaction: <A, E, R>(
    body: (transaction: Transaction) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | SqlError.SqlError, R>;
}

export type PasswordCoordinatorError<E> =
  | E
  | PasswordUnavailable
  | HookConfigurationError
  | SqlError.SqlError;

export const sqlClientPasswordStandaloneGuard = (
  database: unknown,
): Effect.Effect<void, PasswordUnavailable> =>
  sqlClientStandaloneGuard(database, () => PasswordUnavailable.make({}));

export const passwordOptions = (
  configuration: PasswordTargetConfiguration,
  proofMapping?: any,
  coordinated = false,
): PasswordSqlConfiguration => ({
  mode: configuration.mode,
  locking: configuration.locking,

  standaloneGuard: !coordinated ? configuration.standaloneGuard : Effect.void,
  insertIfAbsent: configuration.insertIfAbsent,
  coordinated,
  ...(proofMapping === undefined
    ? {}
    : {
        proof: {
          mapping: proofMapping,
          configuration: {
            mode: configuration.proof.mode,
            locking: configuration.proof.locking,

            standaloneGuard: Effect.void,

            coordinated,
            insertIfAbsent: configuration.proof.insertIfAbsent,
          },
        },
      }),
});

const registrationOptions = (
  configuration: PasswordTargetConfiguration,
  coordinated = false,
): PasswordRegistrationConfiguration => ({
  mode: configuration.mode,
  locking: configuration.locking,

  standaloneGuard: !coordinated ? configuration.standaloneGuard : Effect.void,
  generatedSubjectRows: configuration.generatedSubjectRows,
  coordinated,
});

export const makeTargetPasswordPersistenceServices = (
  database: any,
  mapping: any,
  configuration: PasswordTargetConfiguration,
  proofMapping?: any,
) =>
  Effect.gen(function* () {
    return {
      passwordPersistence: yield* makeSqlPasswordPersistence(
        database,
        mapping,
        passwordOptions(configuration, proofMapping),
      ),
    };
  });

export const makeTargetPasswordRegistrationServices = <Registration>(
  database: any,
  mapping: any,
  configuration: PasswordTargetConfiguration,
) =>
  Effect.gen(function* () {
    return {
      registrationAuthority: yield* makeSqlPasswordRegistrationAuthority<Registration>(
        database,
        mapping,
        registrationOptions(configuration),
      ),
    };
  });

/** Native transaction acquisition exposes SqlError; caller errors propagate unchanged. */
export const coordinateTargetPasswordPersistence = <Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  configuration: PasswordTargetConfiguration,
  proofMapping: any | undefined,
  owner: (
    transaction: Transaction,
    services: { readonly passwordPersistence: PasswordPersistence["Service"] },
  ) => Effect.Effect<A, E, R>,
): Effect.Effect<A, PasswordCoordinatorError<E>, R | LifecycleHooks> =>
  Effect.gen(function* (): Effect.fn.Return<A, PasswordCoordinatorError<E>, R | LifecycleHooks> {
    const hooks = yield* LifecycleHooks;

    if (yield* hasCommitScope) return yield* PasswordUnavailable.make({});
    yield* configuration.coordinatorGuard ?? configuration.standaloneGuard;

    const result = yield* coordinateCommit(
      () =>
        database.transaction((transaction) =>
          Effect.gen(function* () {
            return yield* owner(transaction, {
              passwordPersistence: yield* makeSqlPasswordPersistence(
                transaction as unknown as PasswordSqlDatabase,
                mapping,
                passwordOptions(configuration, proofMapping, true),
              ),
            });
          }),
        ),
      { mode: configuration.mode },
    ).pipe(Effect.provideService(LifecycleHooks, hooks));

    return result.value;
  });

export const coordinateTargetPasswordRegistration = <Registration, Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  configuration: PasswordTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: {
      readonly registrationAuthority: PasswordRegistrationAuthority<Registration>;
    },
  ) => Effect.Effect<A, E, R>,
): Effect.Effect<A, PasswordCoordinatorError<E>, R | LifecycleHooks> =>
  Effect.gen(function* (): Effect.fn.Return<A, PasswordCoordinatorError<E>, R | LifecycleHooks> {
    const hooks = yield* LifecycleHooks;

    if (yield* hasCommitScope) return yield* PasswordUnavailable.make({});
    yield* configuration.coordinatorGuard ?? configuration.standaloneGuard;

    const result = yield* coordinateCommit(
      () =>
        database.transaction((transaction) =>
          Effect.gen(function* () {
            return yield* owner(transaction, {
              registrationAuthority: yield* makeSqlPasswordRegistrationAuthority<Registration>(
                transaction as unknown as PasswordSqlDatabase,
                mapping,
                registrationOptions(configuration, true),
              ),
            });
          }),
        ),
      { mode: configuration.mode },
    ).pipe(Effect.provideService(LifecycleHooks, hooks));

    return result.value;
  });

export const passwordPersistenceLayer = (
  services: Effect.Effect<
    { readonly passwordPersistence: PasswordPersistence["Service"] },
    never,
    LifecycleHooks
  >,
) =>
  Layer.effect(
    PasswordPersistence,
    Effect.map(services, (value) => value.passwordPersistence),
  );

export const passwordRegistrationLayer = <Id, Registration>(
  tag: Context.Key<Id, PasswordRegistrationAuthority<Registration>>,
  services: Effect.Effect<
    { readonly registrationAuthority: PasswordRegistrationAuthority<Registration> },
    never,
    LifecycleHooks
  >,
) =>
  Layer.effect(
    tag,
    Effect.map(services, (value) => value.registrationAuthority),
  );
