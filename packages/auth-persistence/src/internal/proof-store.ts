import type {
  ProofBinding,
  ProofBudget,
  ProofCleanupResult,
  ProofCompletionPlan,
  ProofPersistence,
  ProofPolicy,
  ProofPurpose,
  ProofRecord,
  ProofRequestReceipt,
  ProofVersion,
  ProofUnavailable,
} from "@yielded/auth/Proofs";
import type { SecurityRevision } from "@yielded/auth/Sessions";
import { Context, type Effect } from "effect";

import type {
  ProofAction,
  ProofCommandDecision,
  ProofContinuationRecord,
  ProofDeliveryState,
  ProofGenerationState,
  ProofScopeKind,
} from "./models/proof-model";
import type { PersistenceStoreError } from "./persistence-owner";

export type ProofStoreError = PersistenceStoreError | ProofUnavailable;

export interface ProofAuthorityRead {
  readonly subject:
    | { readonly active: boolean; readonly securityRevision: SecurityRevision }
    | undefined;
  readonly identifierCurrent: boolean;
  readonly credentials: ReadonlyArray<{
    readonly credentialId: string;
    readonly revision: SecurityRevision;
    readonly active: boolean;
  }>;
}

export interface ProofAuthorityRequest {
  readonly moduleId: string;
  readonly purpose: ProofPurpose;
  readonly binding: ProofBinding;
}

export interface ProofScopeEntry {
  readonly kind: ProofScopeKind;
  readonly key: string;
  readonly budget: ProofBudget;
}

export interface ProofScopeRequest {
  readonly moduleId: string;
  readonly purpose: ProofPurpose;
  readonly action: ProofAction;
  readonly entries: ReadonlyArray<ProofScopeEntry>;
}

export interface ProofSeriesKey {
  readonly moduleId: string;
  readonly purpose: ProofPurpose;
  readonly scopeKey: string;
}

export interface ProofSeriesRead {
  readonly activeProofId: string | undefined;
  readonly lastIssueAtMillis: number | undefined;
}

export interface ProofGenerationRead {
  readonly moduleId: string;
  readonly purpose: string;
  readonly proofId: string;
  readonly seriesKey: string;
  readonly version: string;
  readonly deliveryId: string;
  readonly verifierKeyId: string;
  readonly verifierDigest: string;
  readonly expiresAtMillis: number;
  readonly state: ProofGenerationState;
  readonly binding: Effect.Effect<ProofBinding, ProofStoreError>;
  readonly sendCount: number;
  readonly deliveryState: ProofDeliveryState;
  readonly claimVersion: string | undefined;
  readonly claimDeadlineMillis: number | undefined;
  readonly retryAtMillis: number | undefined;
  readonly deliveryRetryMillis: number;
}

export interface ProofRequestRead {
  readonly fingerprint: string;
  readonly proofId: string;
  readonly replay: boolean;
  readonly receipt: Effect.Effect<ProofRequestReceipt, ProofStoreError>;
}

/** The operation retains its own physical preimage. Its write, immediate check,
 * and final prepared-owner registration all remain native to the backend. */
export interface ProofCompletionRead {
  readonly authority: ProofAuthorityRead;
  readonly seriesPresent: boolean;
  readonly continuation:
    | {
        readonly record: ProofContinuationRecord;
        readonly consumed: boolean;
        readonly consumeCompletion: Effect.Effect<void, ProofStoreError>;
      }
    | undefined;
}

export interface ProofCleanupRead {
  readonly result: ProofCleanupResult;
  readonly deleteExpired: Effect.Effect<void, ProofStoreError>;
}

export type ProofAttemptInput = Parameters<ProofPersistence["Service"]["attempt"]>[0];

export type ProofDeliverySettlementInput = Parameters<
  ProofPersistence["Service"]["settleDelivery"]
>[0];

export type ProofAttemptWrite = {
  readonly input: ProofAttemptInput;
  readonly seriesKey: string;
  readonly scopes: ReadonlyArray<ProofScopeEntry>;
  readonly nowMillis: number;
  readonly retentionUntilMillis: number;
} & (
  | { readonly decision: "rejected"; readonly recordFailure: boolean }
  | { readonly decision: "accepted"; readonly continuation: ProofContinuationRecord }
);

export type ProofDeliveryWrite =
  | { readonly transition: "ExpiredClaim"; readonly moduleId: string; readonly proofId: string }
  | {
      readonly transition: "Claim";
      readonly moduleId: string;
      readonly proofId: string;
      readonly sendCount: number;
      readonly claimVersion: ProofVersion;
      readonly claimDeadlineMillis: number;
      readonly retryAtMillis: number;
    }
  | {
      readonly transition: "Settle";
      readonly generation: ProofGenerationRead;
      readonly state: "accepted" | "failed" | "ambiguous";
      readonly retryAtMillis?: number;
    };

export interface ProofCompletionStore {
  readonly readCompletion: (
    input: ProofCompletionPlan["input"],
    mutating: boolean,
  ) => Effect.Effect<ProofCompletionRead, ProofStoreError>;
}

export interface ProofStore extends ProofCompletionStore {
  readonly readAuthority: (
    input: ProofAuthorityRequest,
    locking: boolean,
  ) => Effect.Effect<ProofAuthorityRead, ProofStoreError>;
  readonly lockScopes: (input: ProofScopeRequest) => Effect.Effect<void, ProofStoreError>;
  /** Results correspond to entries; each count scan stops at that entry's limit. */
  readonly readScopeCounts: (
    input: ProofScopeRequest,
    nowMillis: number,
  ) => Effect.Effect<ReadonlyArray<number>, ProofStoreError>;
  readonly readSeries: (
    key: ProofSeriesKey,
    initialVersion?: ProofVersion,
  ) => Effect.Effect<ProofSeriesRead | undefined, ProofStoreError>;
  readonly reserveRequest: (input: {
    readonly record: ProofRecord;
    readonly nowMillis: number;
    readonly retentionUntilMillis: number;
  }) => Effect.Effect<ProofRequestRead, ProofStoreError>;
  readonly readGeneration: (
    moduleId: string,
    proofId: string,
    locking: boolean,
  ) => Effect.Effect<ProofGenerationRead | undefined, ProofStoreError>;
  readonly readAttempt: (input: {
    readonly attempt: ProofAttemptInput;
    readonly seriesKey: string;
    readonly includeSeries: boolean;
  }) => Effect.Effect<
    {
      readonly series: ProofSeriesRead | undefined;
      readonly generation: ProofGenerationRead | undefined;
      readonly command: { readonly decision: ProofCommandDecision } | undefined;
    },
    ProofStoreError
  >;
  readonly readFailureCount: (input: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly seriesKey: string;
    readonly nowMillis: number;
    readonly policy: ProofPolicy;
  }) => Effect.Effect<number, ProofStoreError>;
  readonly publishGeneration: (input: {
    readonly record: ProofRecord;
    readonly policy: ProofPolicy;
    readonly seriesKey: string;
    readonly previousProofId: string | undefined;
    readonly scopes: ReadonlyArray<ProofScopeEntry>;
    readonly nowMillis: number;
    readonly retentionUntilMillis: number;
    readonly nextSeriesVersion: ProofVersion;
  }) => Effect.Effect<void, ProofStoreError>;
  readonly recordAttempt: (input: ProofAttemptWrite) => Effect.Effect<void, ProofStoreError>;
  /** Definite failure discovers and locks its series before its generation. */
  readonly readDeliverySettlement: (
    input: ProofDeliverySettlementInput,
  ) => Effect.Effect<ProofGenerationRead | undefined, ProofStoreError>;
  readonly writeDelivery: (input: ProofDeliveryWrite) => Effect.Effect<void, ProofStoreError>;
  readonly cancelGeneration: (
    key: ProofSeriesKey,
    proofId: string,
  ) => Effect.Effect<void, ProofStoreError>;
  readonly readExpired: (input: {
    readonly moduleId: string;
    readonly nowMillis: number;
    readonly limit: number;
  }) => Effect.Effect<ProofCleanupRead, ProofStoreError>;
}

export class CurrentProofStore extends Context.Service<CurrentProofStore, ProofStore>()(
  "@yielded/auth-persistence/CurrentProofStore",
) {}
