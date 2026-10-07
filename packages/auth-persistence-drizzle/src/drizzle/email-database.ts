import type { AnyProofPersistenceMapping } from "@yielded/auth-persistence/Adapter";
import type { EmailCredentialSnapshot, EmailUnavailable } from "@yielded/auth/Email";
import type { AuthenticationRevision, SecurityRevision } from "@yielded/auth/Sessions";
import { Context, type Effect } from "effect";

import type { NativeSqlDatabase } from "./native-database";
import type { ProofSqlConfiguration } from "./proof-database";

export class CurrentEmailSql extends Context.Service<CurrentEmailSql, NativeSqlDatabase>()(
  "effect-auth/CurrentEmailSql",
) {}

export interface EmailSqlConfiguration {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly maxParameters?: number;
  readonly pgOrderedLocks?: boolean;
  readonly standaloneGuard: Effect.Effect<void, EmailUnavailable>;
  readonly coordinated?: boolean;
  readonly proof?: {
    readonly mapping: AnyProofPersistenceMapping;
    readonly configuration: ProofSqlConfiguration;
  };
}

export interface CurrentAddress {
  readonly nativeSubjectId: unknown;
  readonly subject: Record<string, unknown>;
  readonly revision: AuthenticationRevision;
  readonly source?: {
    readonly credential: Record<string, unknown>;
    readonly identifier: Record<string, unknown>;
    readonly snapshot: EmailCredentialSnapshot;
  };
  readonly targetIdentifier?: Record<string, unknown>;
  readonly targetCredential?: Record<string, unknown>;
  readonly targetIdentifierRevision?: SecurityRevision;
  readonly eligible: boolean;
}
