import type { EmailAddressTarget, EmailUnavailable } from "@yielded/auth/Email";
import type { AuthenticationRequirement, SecurityRevision } from "@yielded/auth/Sessions";
import type { Effect } from "effect";

import type { PersistenceMappingError } from "./mapping-error";

export interface EmailMutationRevisions {
  readonly targetCredentialId: string;
  readonly targetIdentifierRevision: SecurityRevision;
  readonly targetCredentialRevision: SecurityRevision;
  readonly sourceIdentifierRevision: SecurityRevision;
  readonly sourceCredentialRevision: SecurityRevision;
  readonly nextSecurityRevision: SecurityRevision;
}

export interface EmailMutationRead {
  readonly target: EmailAddressTarget;
  readonly requirement: Effect.Effect<
    AuthenticationRequirement,
    EmailUnavailable | PersistenceMappingError
  >;
}
