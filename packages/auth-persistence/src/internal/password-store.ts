import type { PasswordCredentialSnapshot, PasswordUnavailable } from "@yielded/auth/Password";
import type { AuthenticationRequirement, SecurityRevision } from "@yielded/auth/Sessions";
import type { Effect } from "effect";

import type { PersistenceMappingError } from "./mapping-error";

export interface PasswordMutationRevisions {
  readonly credentialId: string;
  readonly credentialRevision: SecurityRevision;
  readonly verifierVersion: SecurityRevision;
  readonly nextSecurityRevision: SecurityRevision;
}

/** Decoded subject-first snapshot used only for this action's policy decision. */
export interface PasswordMutationRead {
  readonly subject:
    | { readonly active: boolean; readonly securityRevision: SecurityRevision }
    | undefined;
  readonly identifierCurrent: boolean;
  readonly credentials: ReadonlyArray<{
    readonly credentialId: string;
    readonly revision: SecurityRevision;
    readonly active: boolean;
  }>;
  readonly snapshot: Effect.Effect<
    PasswordCredentialSnapshot | undefined,
    PasswordUnavailable | PersistenceMappingError
  >;
  readonly requirement: Effect.Effect<
    AuthenticationRequirement,
    PasswordUnavailable | PersistenceMappingError
  >;
}
