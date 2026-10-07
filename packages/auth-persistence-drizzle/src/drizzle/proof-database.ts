import type { ProofUnavailable } from "@yielded/auth/Proofs";
import { Context, type Effect } from "effect";

import type { NativeSqlDatabase, NativeSqlQuery } from "./native-database";

export class CurrentProofSql extends Context.Service<CurrentProofSql, NativeSqlDatabase>()(
  "effect-auth/CurrentProofSql",
) {}

export interface ProofSqlConfiguration {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly maxParameters?: number;
  /** PostgreSQL can sequence authority row locks within a materialized snapshot. */
  readonly pgOrderedLocks?: boolean;
  readonly standaloneGuard: Effect.Effect<void, ProofUnavailable>;
  readonly coordinated?: boolean;
  /** Dialect-native insert-if-absent used to create serialization anchors. */
  readonly insertIfAbsent: (
    query: NativeSqlQuery,
    selfKey: string,
    selfValue: unknown,
  ) => NativeSqlQuery;
}
