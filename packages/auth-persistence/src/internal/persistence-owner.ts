import type { Effect, Schema } from "effect";
import type { SqlError } from "effect/sql/SqlError";

import type { PersistenceMappingError } from "./mapping-error";
import type { QueryFailure } from "./query-failure";

export type PersistenceStoreError =
  | QueryFailure
  | PersistenceMappingError
  | Schema.SchemaError
  | SqlError;

/** Native transaction ownership, independent of table metadata or query shape. */
export interface PersistenceOwner<Operations> {
  readonly read: Operations;
  readonly transaction: <A, E, R>(
    body: (current: Operations) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | PersistenceStoreError, R>;
}
