import { Context, Effect, Option, Predicate } from "effect";
import type * as SqlClient from "effect/unstable/sql/SqlClient";

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

  return Effect.serviceOption(service).pipe(
    Effect.flatMap(
      Option.match({
        onNone: () => Effect.void,
        onSome: () => Effect.fail(unavailable()),
      }),
    ),
  );
};
