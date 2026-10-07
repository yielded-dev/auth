import type { LoginIdentifier } from "@yielded/auth/Identity";
import type {
  PasswordAction,
  PasswordCredentialSnapshot,
  PasswordMutationInput,
  PasswordPersistence,
  PasswordUnavailable,
} from "@yielded/auth/Password";
import type { ProofCompletionPlan } from "@yielded/auth/Proofs";
import type { SubjectId } from "@yielded/auth/Schema";
import type { AuthenticationRequirement, SecurityRevision } from "@yielded/auth/Sessions";
import type { Effect } from "effect";

import type { PersistenceStoreError } from "./persistence-owner";
import type { ProofCompletionRead, ProofCompletionStore, ProofStoreError } from "./proof-store";

export type PasswordStoreError = PersistenceStoreError | ProofStoreError | PasswordUnavailable;

export interface PasswordCredentialLookup {
  readonly moduleId: string;
  readonly identifier: LoginIdentifier;
  readonly subjectId?: SubjectId;
}

export interface PasswordCredentialRead {
  readonly subjectId: SubjectId;
  readonly snapshot: PasswordCredentialSnapshot | undefined;
}

export interface PasswordMutationRevisions {
  readonly credentialId: string;
  readonly credentialRevision: SecurityRevision;
  readonly verifierVersion: SecurityRevision;
  readonly nextSecurityRevision: SecurityRevision;
}

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
  readonly passwordPresent: boolean;
  readonly expectedPasswordCurrent: boolean;
  readonly snapshot: Effect.Effect<PasswordCredentialSnapshot | undefined, PasswordStoreError>;
  readonly requirement: Effect.Effect<AuthenticationRequirement, PasswordStoreError>;
  readonly commandPresent: boolean;
  /** Apply password+authority+subject+receipt together, then assert the exact
   * result. A native prepared owner also registers its final assertion here. */
  readonly applyMutation: (
    revisions: PasswordMutationRevisions,
    commandNowMillis: number,
  ) => Effect.Effect<boolean, PasswordStoreError>;
}

export interface PasswordStore {
  readonly proof?: ProofCompletionStore;
  readonly readCredential: (
    input: PasswordCredentialLookup,
    locking: boolean,
  ) => Effect.Effect<PasswordCredentialRead | undefined, PasswordStoreError>;
  readonly readForSubject: (
    input: Parameters<PasswordPersistence["Service"]["readForSubject"]>[0],
  ) => Effect.Effect<PasswordCredentialSnapshot | undefined, PasswordStoreError>;
  /** Subject -> identifier -> ordered authority credentials -> password -> receipt. */
  readonly readMutation: (
    input: PasswordMutationInput,
    action: PasswordAction,
  ) => Effect.Effect<PasswordMutationRead, PasswordStoreError>;
  /** Both halves observe one database snapshot. */
  readonly readReset: (input: ProofCompletionPlan["input"]) => Effect.Effect<
    {
      readonly credential: PasswordCredentialSnapshot | undefined;
      readonly completion: ProofCompletionRead;
    },
    PasswordStoreError
  >;
}
