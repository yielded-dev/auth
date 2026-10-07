import type { LoginIdentifier } from "@yielded/auth/Identity";
import {
  PasswordUnavailable,
  snapshotPasswordCredential,
  snapshotPasswordRequirement,
  snapshotPasswordRevision,
  type PasswordAction,
  type PasswordCredentialSnapshot,
  type PasswordMutationInput,
} from "@yielded/auth/Password";
import type { ProofCompletionPlan } from "@yielded/auth/Proofs";
import {
  snapshotAuthenticationEvidence,
  type AuthenticationEvidence,
  type AuthenticationRequirement,
  type SecurityRevision,
} from "@yielded/auth/Sessions";
import { DateTime, Effect, Redacted } from "effect";

import { PersistenceMappingError } from "./mapping-error";
import type { PasswordMutationRead } from "./password-store";
import type { ProofWorkflowPolicy } from "./proof-policy";

const unavailable = () => PasswordUnavailable.make({});

export const samePasswordIdentifier = (left: LoginIdentifier, right: LoginIdentifier) =>
  left.namespace === right.namespace && left.value === right.value;

export const samePasswordCredential = (
  left: PasswordCredentialSnapshot,
  right: PasswordCredentialSnapshot,
) =>
  left.moduleId === right.moduleId &&
  left.revision.subjectId === right.revision.subjectId &&
  left.revision.securityRevision === right.revision.securityRevision &&
  left.credentialId === right.credentialId &&
  left.credentialRevision === right.credentialRevision &&
  left.verifierVersion === right.verifierVersion &&
  left.normalization === right.normalization &&
  left.identifierVerifiedAtMillis === right.identifierVerifiedAtMillis &&
  left.revision.credentials.length === right.revision.credentials.length &&
  left.revision.credentials.every((entry) =>
    right.revision.credentials.some(
      (other) => other.credentialId === entry.credentialId && other.revision === entry.revision,
    ),
  ) &&
  left.identifierBindingRevision === right.identifierBindingRevision &&
  samePasswordIdentifier(left.identifier, right.identifier) &&
  Redacted.value(left.verifier) === Redacted.value(right.verifier);

export const passwordEvidenceSatisfiedAt = (
  evidence: AuthenticationEvidence,
  requirement: AuthenticationRequirement,
  now: number,
): boolean => {
  if (evidence.proofs.length > 64 || evidence.revision.credentials.length > 64) return false;
  const revisions = new Map<string, string>();

  for (const item of evidence.revision.credentials) {
    if (revisions.has(item.credentialId)) return false;
    revisions.set(item.credentialId, item.revision);
  }
  if (evidence.proofs.some((proof) => !revisions.has(proof.credentialId))) return false;
  if (evidence.proofs.some((proof) => now < DateTime.toEpochMillis(proof.verifiedAt))) return false;

  const eligible = evidence.proofs.filter((proof) => {
    const age = now - DateTime.toEpochMillis(proof.verifiedAt);

    return age >= 0 && age < requirement.maximumAgeMillis;
  });

  const factors = new Set(eligible.flatMap((proof) => proof.factors));
  const credentials = new Set(eligible.map((proof) => proof.credentialId));

  return requirement.alternatives.some(
    (alternative) =>
      alternative.factors.every((factor) => factors.has(factor)) &&
      credentials.size >= alternative.minimumCredentials &&
      eligible.some(
        (proof) =>
          (!alternative.userVerified || proof.userVerified) &&
          (!alternative.phishingResistant || proof.phishingResistant),
      ),
  );
};

export const snapshotPasswordMutation = Effect.fn("PasswordPersistence.snapshotMutation")(
  function* (input: PasswordMutationInput) {
    const expectedRevision = snapshotPasswordRevision(input.expectedRevision);

    const evidence = yield* snapshotAuthenticationEvidence(input.authorization.evidence).pipe(
      Effect.mapError(unavailable),
    );

    const requirement = yield* snapshotPasswordRequirement(input.authorization.requirement);

    const credential =
      input.credential === undefined
        ? undefined
        : yield* snapshotPasswordCredential(input.credential);

    return Object.freeze({
      ...input,
      expectedRevision,
      replacement: Object.freeze({
        verifier: Redacted.make(Redacted.value(input.replacement.verifier)),
        normalization: input.replacement.normalization,
      }),
      invalidation: Object.freeze({ ...input.invalidation }),
      ...(credential === undefined ? {} : { credential }),
      authorization: Object.freeze({
        challenge: Object.freeze({
          ...input.authorization.challenge,
          revision: snapshotPasswordRevision(input.authorization.challenge.revision),
        }),
        evidence,
        requirement,
      }),
    });
  },
);

export const passwordProofCompletionMatches = (
  input: PasswordMutationInput & { readonly completion: ProofCompletionPlan },
) => {
  const completion = input.completion.input;
  const binding = completion.binding;

  if (
    completion.moduleId !== `${input.moduleId}/reset` ||
    completion.purpose !== "password-reset" ||
    binding._tag !== "Subject" ||
    input.credential === undefined ||
    binding.revision.subjectId !== input.expectedRevision.subjectId ||
    binding.revision.securityRevision !== input.expectedRevision.securityRevision ||
    !samePasswordIdentifier(binding.identifier, input.credential.identifier)
  )
    return false;

  const expected = [...input.expectedRevision.credentials].sort((left, right) =>
    left.credentialId.localeCompare(right.credentialId),
  );

  const actual = [...binding.revision.credentials].sort((left, right) =>
    left.credentialId.localeCompare(right.credentialId),
  );

  return (
    expected.length === actual.length &&
    expected.every(
      (item, index) =>
        item.credentialId === actual[index]!.credentialId &&
        item.revision === actual[index]!.revision,
    )
  );
};

export interface PasswordWorkflowPolicy {
  readonly allocateCredentialId?: Effect.Effect<string, PersistenceMappingError>;
  readonly allocateCredentialIdSync?: () => string;
  readonly allocateRevision?: Effect.Effect<SecurityRevision, PersistenceMappingError>;
  readonly allocateRevisionSync?: () => SecurityRevision;
  readonly subject: {
    readonly nextSecurityRevision?: (
      current: SecurityRevision,
    ) => Effect.Effect<SecurityRevision, PersistenceMappingError>;
    readonly nextSecurityRevisionSync?: (current: SecurityRevision) => SecurityRevision;
  };
  readonly sessionInvalidation: "same-authority-immediate" | "original-absolute-expiry";
}

export interface PasswordWorkflowOptions {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly coordinated?: boolean;
  readonly standaloneGuard: Effect.Effect<void, PasswordUnavailable>;
  readonly proof?: ProofWorkflowPolicy;
}

export const allocatePasswordValue = <A>(
  mode: PasswordWorkflowOptions["mode"],
  asynchronous: Effect.Effect<A, PersistenceMappingError> | undefined,
  synchronous: (() => A) | undefined,
): Effect.Effect<A, PasswordUnavailable | PersistenceMappingError> =>
  mode !== "synchronous" && asynchronous !== undefined
    ? asynchronous
    : synchronous === undefined
      ? Effect.fail(unavailable())
      : Effect.try({
          try: synchronous,
          catch: (cause) => PersistenceMappingError.make({ operation: "mapping", cause }),
        });

export const allocatePasswordNextSecurityRevision = (
  policy: PasswordWorkflowPolicy,
  mode: PasswordWorkflowOptions["mode"],
  current: SecurityRevision,
) =>
  allocatePasswordValue(
    mode,
    policy.subject.nextSecurityRevision?.(current) ?? policy.allocateRevision,
    policy.subject.nextSecurityRevisionSync === undefined
      ? policy.allocateRevisionSync
      : () => policy.subject.nextSecurityRevisionSync!(current),
  );

export const passwordMutationEvidenceMatches = (input: PasswordMutationInput) =>
  !input.expectedRevision.credentials.some(
    (expected) =>
      !input.authorization.evidence.revision.credentials.some(
        (actual) =>
          actual.credentialId === expected.credentialId && actual.revision === expected.revision,
      ),
  );

export const validatePasswordMutation = Effect.fnUntraced(function* (
  policy: PasswordWorkflowPolicy,
  input: PasswordMutationInput,
  action: PasswordAction,
  current: Pick<
    PasswordMutationRead,
    "subject" | "identifierCurrent" | "credentials" | "snapshot" | "requirement"
  >,
) {
  if (
    current.subject === undefined ||
    !current.subject.active ||
    current.subject.securityRevision !== input.expectedRevision.securityRevision
  )
    return undefined;
  const { challenge, evidence } = input.authorization;

  if (
    challenge.moduleId !== input.moduleId ||
    challenge.action !== action ||
    challenge.commandId !== input.commandId ||
    challenge.revision.subjectId !== input.expectedRevision.subjectId ||
    challenge.revision.securityRevision !== input.expectedRevision.securityRevision ||
    (evidence.flowId as string) !== (input.commandId as string) ||
    evidence.bindingDigest !== challenge.bindingDigest ||
    evidence.revision.subjectId !== input.expectedRevision.subjectId ||
    evidence.revision.securityRevision !== input.expectedRevision.securityRevision ||
    (action === "add-password" &&
      (input.credential !== undefined || challenge.targetCredentialId !== undefined))
  )
    return undefined;
  if (!passwordMutationEvidenceMatches(input)) return undefined;
  if (input.credential !== undefined && !current.identifierCurrent) return undefined;

  const expected = new Map(
    [...input.expectedRevision.credentials, ...evidence.revision.credentials].map((item) => [
      item.credentialId,
      item,
    ]),
  );

  if (current.credentials.length !== expected.size) return undefined;
  for (const credential of current.credentials) {
    const wanted = expected.get(credential.credentialId);

    if (wanted === undefined || credential.revision !== wanted.revision || !credential.active)
      return undefined;
    expected.delete(wanted.credentialId);
  }
  if (expected.size !== 0) return undefined;
  if (input.credential !== undefined) {
    const snapshot = yield* current.snapshot;

    if (snapshot === undefined || !samePasswordCredential(snapshot, input.credential))
      return undefined;
  }
  const requirement = yield* current.requirement;
  const now = DateTime.toEpochMillis(yield* DateTime.now);

  if (
    !passwordEvidenceSatisfiedAt(evidence, input.authorization.requirement, now) ||
    !passwordEvidenceSatisfiedAt(evidence, requirement, now)
  )
    return undefined;
  if (
    input.invalidation.existingSessions === "immediate" &&
    policy.sessionInvalidation !== "same-authority-immediate"
  )
    return undefined;

  return now;
});
