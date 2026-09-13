import type { ProofKeyring } from "../proofs/crypto";
import { snapshotProofConfiguration } from "../proofs/module";
import type { ProofPolicy } from "../proofs/policy";

export const defaultPolicy: ProofPolicy = {
  lifetimeMillis: 300_000,
  continuationLifetimeMillis: 30_000,
  maximumFailedAttempts: 5,
  maximumDeliveryAttempts: 1,
  deliveryClaimMillis: 10_000,
  deliveryRetryMillis: 30_000,
  requestRetentionMillis: 3_600_000,
  abuse: {
    issues: { limit: 5, windowMillis: 3_600_000 },
    attempts: { limit: 10, windowMillis: 300_000 },
    subjectIssues: { limit: 5, windowMillis: 3_600_000 },
    subjectAttempts: { limit: 10, windowMillis: 300_000 },
    actionIssues: { limit: 1000, windowMillis: 3_600_000 },
    actionAttempts: { limit: 1000, windowMillis: 300_000 },
    resendCooldownMillis: 30_000,
  },
};

/** Capture the phone method's proof defaults when its descriptor is constructed. */
export const snapshotPhoneConfiguration = <
  Configuration extends {
    readonly template: string;
    readonly keys: ProofKeyring;
    readonly policy?: ProofPolicy;
    readonly digits?: 6 | 7 | 8 | 9 | 10;
  },
>(
  input: Configuration,
) =>
  snapshotProofConfiguration({
    ...input,
    policy: input.policy ?? defaultPolicy,
    secret: { _tag: "NumericCode" as const, digits: input.digits ?? 6 },
  });
