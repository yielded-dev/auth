import { EmailAddressPersistence, EmailSignInTargets, EmailUnavailable } from "@yielded/auth/Email";
import {
  coordinateCommit,
  hasCommitScope,
  LifecycleHooks,
  type HookConfigurationError,
} from "@yielded/auth/Hooks";
/* oxlint-disable no-explicit-any -- public driver wrappers restore concrete Drizzle generics. */
import { type Context, Effect, Layer } from "effect";
import type * as SqlError from "effect/unstable/sql/SqlError";

import {
  makeSqlEmailRegistrationAuthority,
  type EmailRegistrationAuthority,
  type EmailRegistrationConfiguration,
} from "./email-registration";
import {
  makeSqlEmailAddressPersistence,
  makeSqlEmailSignInTargets,
  type EmailSqlConfiguration,
  type EmailSqlDatabase,
  type EmailSqlQuery,
} from "./email-sql";
import type { ProofTargetConfiguration } from "./proof-target";
import { sqlClientStandaloneGuard } from "./standalone-guard";

export interface EmailTargetConfiguration {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly standaloneGuard: Effect.Effect<void, EmailUnavailable>;
  readonly coordinatorGuard?: Effect.Effect<void, EmailUnavailable>;
  readonly generatedSubjectRows: (query: EmailSqlQuery) => EmailSqlQuery;
  readonly proof: ProofTargetConfiguration;
}

interface TransactionOwner<Transaction> {
  readonly transaction: <A, E, R>(
    body: (transaction: Transaction) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | SqlError.SqlError, R>;
}

export type EmailCoordinatorError<E> =
  | E
  | EmailUnavailable
  | HookConfigurationError
  | SqlError.SqlError;

export const sqlClientEmailStandaloneGuard = (
  database: unknown,
): Effect.Effect<void, EmailUnavailable> =>
  sqlClientStandaloneGuard(database, () => EmailUnavailable.make({}));

const proofConfiguration = (configuration: EmailTargetConfiguration, coordinated = false) => ({
  mode: configuration.proof.mode,
  locking: configuration.proof.locking,

  standaloneGuard: Effect.void,
  coordinated,
  insertIfAbsent: configuration.proof.insertIfAbsent,
});

const addressOptions = (
  configuration: EmailTargetConfiguration,
  proofMapping: any,
  coordinated = false,
): EmailSqlConfiguration => ({
  mode: configuration.mode,
  locking: configuration.locking,

  standaloneGuard: !coordinated ? configuration.standaloneGuard : Effect.void,
  coordinated,
  proof: {
    mapping: proofMapping,
    configuration: proofConfiguration(configuration, true),
  },
});

const registrationOptions = (
  configuration: EmailTargetConfiguration,
  proofMapping: any,
  coordinated = false,
): EmailRegistrationConfiguration => ({
  mode: configuration.mode,
  locking: configuration.locking,

  standaloneGuard: !coordinated ? configuration.standaloneGuard : Effect.void,
  generatedSubjectRows: configuration.generatedSubjectRows,
  coordinated,
  proof: {
    mapping: proofMapping,
    configuration: proofConfiguration(configuration, true),
  },
});

export const makeTargetEmailSignInServices = (
  database: any,
  mapping: any,
  configuration: EmailTargetConfiguration,
) =>
  Effect.gen(function* () {
    return {
      emailSignInTargets: yield* makeSqlEmailSignInTargets(database, mapping, {
        mode: configuration.mode,
        locking: false,
        standaloneGuard: configuration.standaloneGuard,
      }),
    };
  });

export const makeTargetEmailAddressServices = (
  database: any,
  mapping: any,
  proofMapping: any,
  configuration: EmailTargetConfiguration,
) =>
  Effect.gen(function* () {
    return {
      emailAddressPersistence: yield* makeSqlEmailAddressPersistence(
        database,
        mapping,
        addressOptions(configuration, proofMapping),
      ),
    };
  });

export const makeTargetEmailRegistrationServices = <Registration>(
  database: any,
  mapping: any,
  proofMapping: any,
  configuration: EmailTargetConfiguration,
) =>
  Effect.gen(function* () {
    return {
      registrationAuthority: yield* makeSqlEmailRegistrationAuthority<Registration>(
        database,
        mapping,
        registrationOptions(configuration, proofMapping),
      ),
    };
  });

export const coordinateTargetEmailAddress = <Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  proofMapping: any,
  configuration: EmailTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: { readonly emailAddressPersistence: EmailAddressPersistence["Service"] },
  ) => Effect.Effect<A, E, R>,
): Effect.Effect<A, EmailCoordinatorError<E>, R | LifecycleHooks> =>
  Effect.gen(function* (): Effect.fn.Return<A, EmailCoordinatorError<E>, R | LifecycleHooks> {
    const hooks = yield* LifecycleHooks;

    if (yield* hasCommitScope) return yield* EmailUnavailable.make({});
    yield* configuration.coordinatorGuard ?? configuration.standaloneGuard;

    const result = yield* coordinateCommit(
      () =>
        database.transaction((transaction) =>
          Effect.gen(function* () {
            return yield* owner(transaction, {
              emailAddressPersistence: yield* makeSqlEmailAddressPersistence(
                transaction as unknown as EmailSqlDatabase,
                mapping,
                addressOptions(configuration, proofMapping, true),
              ),
            });
          }),
        ),
      { mode: configuration.mode },
    ).pipe(Effect.provideService(LifecycleHooks, hooks));

    return result.value;
  });

export const coordinateTargetEmailRegistration = <Registration, Transaction, A, E, R>(
  database: TransactionOwner<Transaction>,
  mapping: any,
  proofMapping: any,
  configuration: EmailTargetConfiguration,
  owner: (
    transaction: Transaction,
    services: { readonly registrationAuthority: EmailRegistrationAuthority<Registration> },
  ) => Effect.Effect<A, E, R>,
): Effect.Effect<A, EmailCoordinatorError<E>, R | LifecycleHooks> =>
  Effect.gen(function* (): Effect.fn.Return<A, EmailCoordinatorError<E>, R | LifecycleHooks> {
    const hooks = yield* LifecycleHooks;

    if (yield* hasCommitScope) return yield* EmailUnavailable.make({});
    yield* configuration.coordinatorGuard ?? configuration.standaloneGuard;

    const result = yield* coordinateCommit(
      () =>
        database.transaction((transaction) =>
          Effect.gen(function* () {
            return yield* owner(transaction, {
              registrationAuthority: yield* makeSqlEmailRegistrationAuthority<Registration>(
                transaction as unknown as EmailSqlDatabase,
                mapping,
                registrationOptions(configuration, proofMapping, true),
              ),
            });
          }),
        ),
      { mode: configuration.mode },
    ).pipe(Effect.provideService(LifecycleHooks, hooks));

    return result.value;
  });

export const emailSignInTargetsLayer = (
  services: Effect.Effect<{ readonly emailSignInTargets: EmailSignInTargets["Service"] }>,
) =>
  Layer.effect(
    EmailSignInTargets,
    Effect.map(services, (value) => value.emailSignInTargets),
  );

export const emailAddressPersistenceLayer = (
  services: Effect.Effect<
    { readonly emailAddressPersistence: EmailAddressPersistence["Service"] },
    never,
    LifecycleHooks
  >,
) =>
  Layer.effect(
    EmailAddressPersistence,
    Effect.map(services, (value) => value.emailAddressPersistence),
  );

export const emailRegistrationLayer = <Id, Registration>(
  tag: Context.Key<Id, EmailRegistrationAuthority<Registration>>,
  services: Effect.Effect<
    { readonly registrationAuthority: EmailRegistrationAuthority<Registration> },
    never,
    LifecycleHooks
  >,
) =>
  Layer.effect(
    tag,
    Effect.map(services, (value) => value.registrationAuthority),
  );
