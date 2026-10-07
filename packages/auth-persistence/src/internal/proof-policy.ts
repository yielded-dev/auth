import {
  ProofBinding,
  ProofUnavailable,
  type ProofPolicy,
  type ProofPurpose,
  type ProofVersion,
} from "@yielded/auth/Proofs";
import { Effect, Schema } from "effect";

import { PersistenceMappingError } from "./mapping-error";
import type { ProofAction, ProofScopeKeys } from "./models/proof-model";
import type { ProofAuthorityRead, ProofScopeEntry } from "./proof-store";

export interface ProofWorkflowPolicy {
  readonly scopeKeys: (input: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly binding: ProofBinding;
  }) => ProofScopeKeys;
  readonly allocateVersion?: Effect.Effect<ProofVersion, PersistenceMappingError>;
  readonly allocateVersionSync?: () => ProofVersion;
}

export interface ProofWorkflowOptions {
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  readonly coordinated?: boolean;
  readonly standaloneGuard: Effect.Effect<void, ProofUnavailable>;
}

export const allocateProofVersion = (
  policy: ProofWorkflowPolicy,
  mode: ProofWorkflowOptions["mode"],
): Effect.Effect<ProofVersion, ProofUnavailable | PersistenceMappingError> => {
  if (mode !== "synchronous" && policy.allocateVersion !== undefined) return policy.allocateVersion;

  return policy.allocateVersionSync === undefined
    ? Effect.fail(ProofUnavailable.make({}))
    : Effect.try({
        try: policy.allocateVersionSync,
        catch: (cause) => PersistenceMappingError.make({ operation: "mapping", cause }),
      });
};

const canonicalBinding = Schema.encodeSync(Schema.fromJsonString(ProofBinding));

export const sameProofBinding = (left: ProofBinding, right: ProofBinding): boolean =>
  canonicalBinding(left) === canonicalBinding(right);

export const proofScopeEntries = (
  keys: ProofScopeKeys,
  binding: ProofBinding,
  action: ProofAction,
  policy: ProofPolicy,
): ReadonlyArray<ProofScopeEntry> => {
  const suffix = action === "issue" ? "Issues" : "Attempts";
  const simple = action === "issue" ? "issues" : "attempts";

  const entries: ProofScopeEntry[] = [
    { kind: "action", key: "*", budget: policy.abuse[`action${suffix}`] },
    { kind: "identifier", key: keys.identifier, budget: policy.abuse[simple] },
  ];

  if (binding._tag !== "Identifier")
    entries.push({ kind: "subject", key: keys.subject, budget: policy.abuse[`subject${suffix}`] });

  return entries;
};

export const matchesProofAuthority = (
  binding: ProofBinding,
  current: ProofAuthorityRead,
): boolean => {
  if (!current.identifierCurrent) return false;
  if (binding._tag === "Identifier") return true;
  if (
    current.subject === undefined ||
    !current.subject.active ||
    current.subject.securityRevision !== binding.revision.securityRevision
  )
    return false;

  const expected = [...binding.revision.credentials].sort((a, b) =>
    a.credentialId.localeCompare(b.credentialId),
  );

  const actual = [...current.credentials].sort((a, b) =>
    a.credentialId.localeCompare(b.credentialId),
  );

  return (
    actual.length === expected.length &&
    actual.every(
      (item, index) =>
        item.active &&
        item.credentialId === expected[index]?.credentialId &&
        item.revision === expected[index]?.revision,
    )
  );
};
