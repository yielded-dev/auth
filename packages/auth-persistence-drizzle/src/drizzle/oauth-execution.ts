import type { NativeDatabase } from "@yielded/auth-persistence/Adapter";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import type { OAuthUnavailable } from "@yielded/auth/OAuth";
/* oxlint-disable no-explicit-any -- concrete driver entry points restore table/database generics. */
import { Effect } from "effect";
import type { Statement } from "effect/sql/Statement";

import type { PersistenceMappingError } from "./model";
import { CurrentOAuthTransaction, type OAuthNativeDatabase } from "./oauth-owner";
import { captureOAuthMapping, nonce, unavailable } from "./oauth-state";
import { validateDrizzleStorage } from "./storage-validation";
import {
  coordinateTransactionOwner,
  makeTransactionExecution,
  sqlClientTransactionStandaloneGuard,
  type TransactionTargetConfiguration,
  type TransactionCoordinatorError,
  type TransactionExecution,
} from "./transaction-execution";

export type OAuthTargetConfiguration = TransactionTargetConfiguration<OAuthUnavailable>;
export type OAuthCoordinatorError<E> = TransactionCoordinatorError<E, OAuthUnavailable>;
export type OAuthExecution = TransactionExecution<OAuthUnavailable, CurrentOAuthTransaction, never>;

export const sqlClientOAuthStandaloneGuard = (
  service: Parameters<typeof sqlClientTransactionStandaloneGuard>[1],
) => sqlClientTransactionStandaloneGuard(unavailable, service);

export const makeOAuthExecution = Effect.fnUntraced(function* (
  configuration: OAuthTargetConfiguration,
  mapping: unknown,
): Effect.fn.Return<OAuthExecution, OAuthUnavailable, LifecycleHooks | NativeDatabase> {
  const hooks = yield* LifecycleHooks;

  yield* validateDrizzleStorage(mapping).pipe(Effect.mapError(unavailable));

  const execution = yield* makeTransactionExecution(
    CurrentOAuthTransaction,
    configuration,
    unavailable,
    nonce,
  );

  return {
    ...execution,
    run: (operation, mutation) =>
      execution.run(operation, mutation).pipe(Effect.provideService(LifecycleHooks, hooks)),
  };
});

export const coordinateOAuthOwner = <Services, Transaction, A, E, R>(
  database: OAuthNativeDatabase,
  mapping: any,
  configuration: OAuthTargetConfiguration,
  allocate: (mapping: any) => Effect.Effect<any, PersistenceMappingError>,
  services: (mapping: any, execution: OAuthExecution, resources: any) => Services,
  owner: (
    transaction: Transaction,
    services: Services,
    append: (statement: Statement<any>) => void,
  ) => Effect.Effect<A, E, R>,
): Effect.Effect<A, OAuthCoordinatorError<E>, R | LifecycleHooks | NativeDatabase> => {
  const captured = captureOAuthMapping(mapping);

  return Effect.flatMap(LifecycleHooks, (hooks) =>
    coordinateTransactionOwner(
      database,
      CurrentOAuthTransaction,
      configuration,
      validateDrizzleStorage(captured).pipe(
        Effect.andThen(Effect.suspend(() => allocate(captured))),
      ),
      unavailable,
      nonce,
      (execution, resources) =>
        services(
          captured,
          {
            ...execution,
            run: (operation, mutation) =>
              execution.run(operation, mutation).pipe(Effect.provideService(LifecycleHooks, hooks)),
          },
          resources,
        ),
      owner,
    ).pipe(Effect.provideService(LifecycleHooks, hooks)),
  );
};
