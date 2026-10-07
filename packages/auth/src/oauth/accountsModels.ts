import { Schema } from "effect";

import { RequestBindingFlowId } from "../operations/requestBinding";
import { TokenDigest } from "../Schema";
import { SessionInvalidationWindow } from "../sessions/invalidation";
import {
  AuthenticationEvidence,
  AuthenticationRequirement,
  AuthenticationProof,
  AssuranceAlternative,
  SessionId,
} from "../sessions/models";
import {
  OAuthCredentialSnapshot,
  OAuthInstant,
  OAuthModuleId,
  OAuthSealedTransaction,
  OAuthSignInAccess,
  OAuthSignInBegin,
  OAuthSignInComplete,
  OAuthSignInPolicy,
  OAuthSignInTransactionContext,
  OAuthCommandId,
} from "./signInModels";

export class OAuthActionRequired extends Schema.TaggedError<OAuthActionRequired>()(
  "OAuthActionRequired",
  {},
) {}

export const OAuthAccountsPolicy = Schema.Struct({
  ...OAuthSignInPolicy.fields,
  maximumEvidenceAgeMillis: Schema.Int.check(Schema.isBetween({ minimum: 1000, maximum: 300000 })),
  /** Applies only to unlink, including any positive session-cache window. */
  requireImmediateInvalidation: Schema.Boolean,
});

export type OAuthAccountsPolicy = typeof OAuthAccountsPolicy.Type;

export const OAuthActionDigest = TokenDigest.check(
  Schema.isPattern(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/),
);

export const OAuthAccountRevision = OAuthCredentialSnapshot.fields.revision;
export type OAuthAccountRevision = typeof OAuthAccountRevision.Type;

const proof = Schema.optionalKey(
  Schema.RedactedFromValue(Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(16384))),
);

export const OAuthLinkBegin = Schema.Struct({ ...OAuthSignInBegin.fields, actionProof: proof });
export const OAuthLinkComplete = Schema.Struct({ ...OAuthSignInComplete.fields });

export const OAuthUnlink = Schema.Struct({
  commandId: OAuthCommandId,
  credentialId: OAuthCredentialSnapshot.fields.credentialId,
  actionProof: proof,
});

export const OAuthActionChallenge = Schema.Struct({
  moduleId: OAuthModuleId,
  action: Schema.Literals(["link-begin", "unlink"]),
  flowId: RequestBindingFlowId,
  revision: OAuthAccountRevision,
  /** Hash of the exact pre-authorization link intent or unlink credential. */
  intentDigest: OAuthActionDigest,
  bindingDigest: OAuthActionDigest,
});

export type OAuthActionChallenge = typeof OAuthActionChallenge.Type;

/** Session is accepted only with its exact private provenance, validated by the
 * application authority. Public assurance ordinals never identify credentials. */
export const OAuthActionSource = Schema.Union([
  Schema.TaggedStruct("Proof", {}),
  Schema.TaggedStruct("Session", {
    sessionId: SessionId.check(Schema.isMaxLength(256)),
    authenticatedAt: Schema.DateTimeUtcFromMillis,
  }),
]);

export type OAuthActionSource = typeof OAuthActionSource.Type;

export const OAuthActionAuthorization = Schema.Struct({
  challenge: OAuthActionChallenge,
  source: OAuthActionSource,
  /** Fixed at the accepted action; completion never refreshes its lifetime. */
  validUntilMillis: OAuthInstant,
  evidence: Schema.Struct({
    ...AuthenticationEvidence.fields,
    revision: OAuthAccountRevision,
    flowId: AuthenticationEvidence.fields.flowId.check(Schema.isMaxLength(256)),
    bindingDigest: OAuthActionDigest,
    proofs: Schema.NonEmptyArray(
      Schema.Struct({
        ...AuthenticationProof.fields,
        method: Schema.NonEmptyString.check(Schema.isMaxLength(128)),
        credentialId: OAuthCredentialSnapshot.fields.credentialId,
        factors: AuthenticationProof.fields.factors.check(Schema.isMaxLength(8)),
      }),
    ).check(Schema.isMaxLength(64)),
  }),
  requirement: Schema.Struct({
    ...AuthenticationRequirement.fields,
    alternatives: Schema.NonEmptyArray(
      Schema.Struct({
        ...AssuranceAlternative.fields,
        factors: AssuranceAlternative.fields.factors.check(Schema.isMaxLength(8)),
        minimumCredentials: Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 64 })),
      }),
    ).check(Schema.isMaxLength(64)),
  }),
});

export type OAuthActionAuthorization = typeof OAuthActionAuthorization.Type;

/** Hash this intent before authorizing it; the final encrypted context then
 * includes the accepted authorization without a self-referential digest. */
export const OAuthLinkIntentContext = Schema.Struct({
  ...OAuthSignInTransactionContext.fields,
  namespace: Schema.Literal("effect-auth/oauth-link-context/v1"),
  revision: OAuthAccountRevision,
  maximumEvidenceAgeMillis: OAuthAccountsPolicy.fields.maximumEvidenceAgeMillis,
});

export type OAuthLinkIntentContext = typeof OAuthLinkIntentContext.Type;

export const OAuthLinkTransactionContext = Schema.Struct({
  ...OAuthLinkIntentContext.fields,
  authorization: OAuthActionAuthorization,
});

export type OAuthLinkTransactionContext = typeof OAuthLinkTransactionContext.Type;

export const OAuthLinkFlow = Schema.Struct({
  context: OAuthLinkTransactionContext,
  sealed: OAuthSealedTransaction,
});

export type OAuthLinkFlow = typeof OAuthLinkFlow.Type;

export const OAuthLinked = Schema.TaggedStruct("Linked", {
  credentialId: OAuthCredentialSnapshot.fields.credentialId,
  changed: Schema.Boolean,
  returnTarget: OAuthLinkTransactionContext.fields.returnTarget,
});

export const OAuthUnlinked = Schema.TaggedStruct("Unlinked", {
  credentialId: OAuthCredentialSnapshot.fields.credentialId,
  invalidation: SessionInvalidationWindow,
});

export const OAuthLinkResult = Schema.Union([
  OAuthLinked,
  Schema.TaggedStruct("Cancelled", {
    returnTarget: OAuthLinkTransactionContext.fields.returnTarget,
  }),
]);

export const OAuthLinkAccess = Schema.Struct({
  ...OAuthSignInAccess.fields,
  subjectId: OAuthAccountRevision.fields.subjectId,
});

export type OAuthLinkAccess = typeof OAuthLinkAccess.Type;

export const OAuthLinkIssueDecision = Schema.Union([
  Schema.TaggedStruct("Issued", { flow: OAuthLinkFlow }),
  Schema.TaggedStruct("Rejected", {}),
]);

export const OAuthLinkConsumeDecision = Schema.Union([
  Schema.TaggedStruct("Consumed", { flow: OAuthLinkFlow }),
  Schema.TaggedStruct("Rejected", {}),
]);

export const OAuthLinkDecision = Schema.Union([
  Schema.TaggedStruct("Linked", { credential: OAuthCredentialSnapshot, changed: Schema.Boolean }),
  Schema.TaggedStruct("Rejected", {}),
  Schema.TaggedStruct("Conflict", {}),
]);

export const OAuthCredentialKey = Schema.Struct({
  moduleId: OAuthModuleId,
  subjectId: OAuthAccountRevision.fields.subjectId,
  credentialId: OAuthCredentialSnapshot.fields.credentialId,
});

export type OAuthCredentialKey = typeof OAuthCredentialKey.Type;

export const OAuthUnlinkDecision = Schema.Union([
  Schema.TaggedStruct("Unlinked", { result: OAuthUnlinked }),
  Schema.TaggedStruct("Rejected", {}),
  Schema.TaggedStruct("LastSignInMethod", {}),
]);
