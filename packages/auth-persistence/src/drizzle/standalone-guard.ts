import { Context, Effect, Predicate } from "effect";
import type * as SqlClient from "effect/unstable/sql/SqlClient";

import { requireStandalone } from "../internal/standalone";

type TransactionService = Context.Key<
  SqlClient.TransactionConnection,
  SqlClient.TransactionConnection.Service
>;

const transactionService = (database: unknown): TransactionService | undefined => {
  if (
    !Predicate.hasProperty(database, "$client") ||
    !Predicate.hasProperty(database.$client, "transactionService") ||
    !Context.isKey(database.$client.transactionService)
  ) {
    return undefined;
  }

  return database.$client.transactionService;
};

/** Bind the client-specific transaction marker at foreign adapter construction. */
export const sqlClientStandaloneGuard = <Failure>(
  database: unknown,
  unavailable: () => Failure,
): Effect.Effect<void, Failure> => {
  const service = transactionService(database);

  if (service === undefined) return Effect.suspend(() => Effect.fail(unavailable()));

  return requireStandalone(unavailable, { transactionService: service });
};
