import { LoginIdentifier } from "@yielded/auth/Identity";
import {
  PasskeyCeremony,
  PasskeyClaim,
  PasskeyCredential,
  PasskeyCredentialSummary,
  PasskeyMethodPolicy,
  PasskeyRemoved,
  PasskeyUserHandle,
} from "@yielded/auth/Passkey";
import {
  PasswordAttemptId,
  PasswordCredentialSnapshot,
  PasswordReplacement,
} from "@yielded/auth/Password";
import {
  ProofBinding,
  ProofContinuationId,
  ProofDeliveryId,
  ProofId,
  ProofPolicy,
  ProofPurpose,
  ProofRequestId,
  ProofRequestReceipt,
  ProofVersion,
} from "@yielded/auth/Proofs";
import { Email, SubjectId, TokenDigest } from "@yielded/auth/Schema";
import {
  SecurityRevision,
  SessionAuthenticationProvenance,
  SessionCredentialVersion,
  SessionMetadata,
} from "@yielded/auth/Sessions";
import { Schema } from "effect";

import { Claims, Registration, Username } from "./contract";

export const Customer = Schema.Struct({
  id: SubjectId,
  active: Schema.Boolean,
  securityRevision: SecurityRevision,
  displayName: Schema.String,
  username: Username,
  email: Email,
  identifierRevision: SecurityRevision,
  verifiedAtMillis: Schema.optionalKey(Schema.Int),
  emailCredential: Schema.optionalKey(
    Schema.Struct({ id: Schema.NonEmptyString, revision: SecurityRevision }),
  ),
});

export type Customer = typeof Customer.Type;

const Password = Schema.Struct({
  subjectId: SubjectId,
  credentialId: Schema.NonEmptyString,
  revision: SecurityRevision,
  verifierVersion: SecurityRevision,
  replacement: PasswordReplacement,
});

export const Session = Schema.Struct({
  ...SessionMetadata.fields,
  claims: Claims,
  digest: TokenDigest,
  version: SecurityRevision,
  provenance: SessionAuthenticationProvenance,
  credentialVersion: SessionCredentialVersion,
});

export type Session = typeof Session.Type;

const Attempt = Schema.Struct({
  id: PasswordAttemptId,
  moduleId: Schema.NonEmptyString,
  action: Schema.Literals(["sign-in", "change"]),
  captured: Schema.optionalKey(PasswordCredentialSnapshot),
  pending: Schema.Boolean,
  deadline: Schema.Int,
  retentionUntil: Schema.Int,
});

export const ProofRecord = Schema.Struct({
  moduleId: Schema.NonEmptyString,
  purpose: ProofPurpose,
  proofId: ProofId,
  requestId: ProofRequestId,
  fingerprint: TokenDigest,
  deliveryId: ProofDeliveryId,
  binding: ProofBinding,
  verifier: Schema.Struct({ keyId: Schema.NonEmptyString, digest: TokenDigest }),
  issuedAtMillis: Schema.Int,
  expiresAtMillis: Schema.Int,
  version: ProofVersion,
});

const Proof = Schema.Struct({
  record: ProofRecord,
  policy: ProofPolicy,
  series: Schema.String,
  state: Schema.Literals(["active", "consumed", "superseded", "cancelled"]),
  retentionUntil: Schema.Int,
  sendCount: Schema.Natural,
  deliveryState: Schema.Literals(["new", "claimed", "accepted", "failed", "ambiguous"]),
  claimVersion: Schema.optionalKey(ProofVersion),
  claimDeadline: Schema.optionalKey(Schema.Int),
  retryAt: Schema.optionalKey(Schema.Int),
});

const Continuation = Schema.Struct({
  moduleId: Schema.NonEmptyString,
  purpose: ProofPurpose,
  id: ProofContinuationId,
  digest: TokenDigest,
  proofId: ProofId,
  binding: ProofBinding,
  expiresAt: Schema.Int,
  consumed: Schema.Boolean,
  retentionUntil: Schema.Int,
});

const Passkey = Schema.Struct({ credential: PasskeyCredential, summary: PasskeyCredentialSummary });

const Ceremony = Schema.Struct({
  ceremony: PasskeyCeremony,
  policy: PasskeyMethodPolicy,
  state: Schema.Literals(["pending", "claimed", "verified", "rejected", "ambiguous"]),
  claim: Schema.optionalKey(PasskeyClaim),
  credential: Schema.optionalKey(PasskeyCredential),
});

/** Application records, not SQL roles. Every disk value is decoded before use. */
export const Database = Schema.Struct({
  version: Schema.Literal(1),
  sequence: Schema.Natural,
  customers: Schema.Array(Customer),
  passwords: Schema.Array(Password),
  sessions: Schema.Array(Session),
  flows: Schema.Array(Schema.Struct({ id: Schema.String, expiresAt: Schema.Int })),
  attempts: Schema.Array(Attempt),
  registrations: Schema.Array(
    Schema.Struct({
      requestId: Schema.String,
      identifier: LoginIdentifier,
      registration: Registration,
      replacement: PasswordReplacement,
    }),
  ),
  charges: Schema.Array(
    Schema.Struct({ bucket: Schema.String, at: Schema.Int, retentionUntil: Schema.Int }),
  ),
  proofRequests: Schema.Array(
    Schema.Struct({
      moduleId: Schema.String,
      fingerprint: TokenDigest,
      receipt: ProofRequestReceipt,
      retentionUntil: Schema.Int,
    }),
  ),
  proofs: Schema.Array(Proof),
  continuations: Schema.Array(Continuation),
  passkeys: Schema.Array(Passkey),
  handles: Schema.Array(
    Schema.Struct({ rpId: Schema.String, subjectId: SubjectId, handle: PasskeyUserHandle }),
  ),
  ceremonies: Schema.Array(Ceremony),
  renames: Schema.Array(
    Schema.Struct({
      moduleId: Schema.String,
      commandId: Schema.String,
      subjectId: SubjectId,
      name: Schema.String,
      result: PasskeyCredentialSummary,
      retentionUntil: Schema.Int,
    }),
  ),
  removals: Schema.Array(
    Schema.Struct({
      moduleId: Schema.String,
      commandId: Schema.String,
      subjectId: SubjectId,
      result: PasskeyRemoved,
      retentionUntil: Schema.Int,
    }),
  ),
  mutations: Schema.Array(
    Schema.Struct({
      moduleId: Schema.String,
      commandId: Schema.String,
      subjectId: SubjectId,
      kind: Schema.Literals(["email", "password"]),
      retentionUntil: Schema.Int,
    }),
  ),
});

export type State = { -readonly [K in keyof typeof Database.Type]: (typeof Database.Type)[K] };

export const emptyDatabase = (): State => ({
  version: 1,
  sequence: 0,
  customers: [],
  passwords: [],
  sessions: [],
  flows: [],
  attempts: [],
  registrations: [],
  charges: [],
  proofRequests: [],
  proofs: [],
  continuations: [],
  passkeys: [],
  handles: [],
  ceremonies: [],
  renames: [],
  removals: [],
  mutations: [],
});

export const nextId = (state: State, prefix: string) => `${prefix}-${++state.sequence}`;

export interface Budget {
  readonly bucket: string;
  readonly limit: number;
  readonly windowMillis: number;
}

/** Charge each open bucket, even when another bucket denies the command. */
export const charge = (state: State, budgets: ReadonlyArray<Budget>, now: number) => {
  const open = budgets.filter(
    (budget) =>
      state.charges.filter(
        (event) => event.bucket === budget.bucket && event.at >= now - budget.windowMillis,
      ).length < budget.limit,
  );

  state.charges = [
    ...state.charges,
    ...open.map((budget) => ({
      bucket: budget.bucket,
      at: now,
      retentionUntil: now + budget.windowMillis,
    })),
  ];

  return open.length === budgets.length;
};
