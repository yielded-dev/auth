import type {
  EmailAction,
  EmailAddressMutation,
  EmailAddressPersistence,
  EmailAddressTarget,
  EmailUnavailable,
} from "@yielded/auth/Email";
import type { ProofCompletionInput } from "@yielded/auth/Proofs";
import type {
  AuthenticationRequirement,
  AuthenticationRevision,
  SecurityRevision,
} from "@yielded/auth/Sessions";
import type { Effect } from "effect";

import type { PersistenceStoreError } from "./persistence-owner";
import type { ProofCompletionRead, ProofCompletionStore, ProofStoreError } from "./proof-store";

export type EmailStoreError = PersistenceStoreError | ProofStoreError | EmailUnavailable;
export type EmailAddressRequest = Parameters<EmailAddressPersistence["Service"]["target"]>[0];

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
  readonly requirement: Effect.Effect<AuthenticationRequirement, EmailStoreError>;
  readonly commandPresent: boolean;
  readonly applyMutation: (
    allocated: EmailMutationRevisions,
    nowMillis: number,
  ) => Effect.Effect<boolean, EmailStoreError>;
}

export interface EmailAddressStore {
  readonly proof?: ProofCompletionStore;
  readonly readAddress: (
    input: EmailAddressRequest,
    locking: boolean,
  ) => Effect.Effect<EmailAddressTarget | undefined, EmailStoreError>;
  readonly readMutation: (
    input: EmailAddressMutation,
    action: EmailAction,
  ) => Effect.Effect<EmailMutationRead | undefined, EmailStoreError>;
  /** Email authority and proof are decoded from one database snapshot. */
  readonly readCompletion: (input: ProofCompletionInput) => Effect.Effect<
    {
      readonly revision: AuthenticationRevision | undefined;
      readonly completion: ProofCompletionRead;
    },
    EmailStoreError
  >;
  readonly readExpired: (input: {
    readonly moduleId: string;
    readonly nowMillis: number;
    readonly limit: number;
  }) => Effect.Effect<
    {
      readonly result: { readonly removed: number; readonly hasMore: boolean };
      readonly deleteExpired: Effect.Effect<void, EmailStoreError>;
    },
    EmailStoreError
  >;
}
