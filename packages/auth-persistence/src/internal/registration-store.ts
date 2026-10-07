import type { LoginIdentifier } from "@yielded/auth/Identity";
import type { PasswordReplacement, PasswordUnavailable } from "@yielded/auth/Password";
import type { SubjectId } from "@yielded/auth/Schema";
import type { SecurityRevision } from "@yielded/auth/Sessions";
import type { Effect } from "effect";

import type { PersistenceStoreError } from "./persistence-owner";

export interface PasswordRegistrationStore {
  readonly reserve: (input: {
    readonly moduleId: string;
    readonly requestId: string;
  }) => Effect.Effect<boolean, PersistenceStoreError>;
  readonly identifierAvailable: (
    identifier: LoginIdentifier,
  ) => Effect.Effect<boolean, PersistenceStoreError>;
  /** Validate the provisioned subject and bind the unverified identifier,
   * password, and authority credential in this same owner. */
  readonly bindSubject: (input: {
    readonly moduleId: string;
    readonly identifier: LoginIdentifier;
    readonly subjectId: SubjectId;
    readonly replacement: PasswordReplacement;
    readonly identifierRevision: SecurityRevision;
    readonly credentialId: string;
    readonly credentialRevision: SecurityRevision;
    readonly verifierVersion: SecurityRevision;
  }) => Effect.Effect<boolean, PersistenceStoreError | PasswordUnavailable>;
}
