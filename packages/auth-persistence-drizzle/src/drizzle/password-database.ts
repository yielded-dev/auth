import type { AnyProofPersistenceMapping } from "@yielded/auth-persistence/Adapter";
import type { PasswordUnavailable } from "@yielded/auth/Password";
import { Context, type Effect } from "effect";

import type { NativeSqlDatabase, NativeSqlQuery } from "./native-database";
import type { ProofSqlConfiguration } from "./proof-database";

export class CurrentPasswordSql extends Context.Service<CurrentPasswordSql, NativeSqlDatabase>()(
  "effect-auth/CurrentPasswordSql",
) {}

export interface PasswordSqlConfiguration {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly maxParameters?: number;
  readonly standaloneGuard: Effect.Effect<void, PasswordUnavailable>;
  readonly coordinated?: boolean;
  readonly insertIfAbsent: (
    query: NativeSqlQuery,
    selfKey: string,
    selfValue: unknown,
  ) => NativeSqlQuery;
  readonly proof?: {
    readonly mapping: AnyProofPersistenceMapping;
    readonly configuration: ProofSqlConfiguration;
  };
}
