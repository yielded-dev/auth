import type {
  ProofBinding,
  ProofContinuationId,
  ProofId,
  ProofPurpose,
  ProofRequestReceipt,
  ProofVersion,
  ProofPolicy,
  ProofRecord,
} from "@yielded/auth/Proofs";
import type { TokenDigest } from "@yielded/auth/Schema";
import type { InferInsertModel, InferSelectModel, SQL, Table } from "drizzle-orm";
import type { Effect } from "effect";

import type { PersistenceMappingError, SubjectIdCodec } from "./model";

type ColumnKey<T extends Table> = Extract<keyof T["_"]["columns"], string>;

export type ProofAction = "issue" | "attempt";
export type ProofScopeKind = "action" | "identifier" | "subject";
export type ProofGenerationState = "active" | "consumed" | "cancelled" | "superseded";
export type ProofDeliveryState = "new" | "claimed" | "accepted" | "failed" | "ambiguous";
export type ProofCommandKind = "attempt" | "complete";
export type ProofCommandDecision = "accepted" | "rejected" | "completed";

export interface ProofScopeKeys {
  /** Stable across flow/context/request changes and bounded by the consumer codec. */
  readonly series: string;
  readonly identifier: string;
  /** A tagged non-null value; use a stable sentinel when the binding has no subject. */
  readonly subject: string;
}

export interface ProofAuthorityInput<NativeSubjectId> {
  readonly moduleId: string;
  readonly purpose: ProofPurpose;
  readonly binding: ProofBinding;
  /** Resolved by Effect preplanning before an interactive check or D1 predicate compile. */
  readonly nativeSubjectId?: NativeSubjectId;
}

export interface ProofAuthorityTables<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> {
  readonly identifier: {
    readonly table: Identifier;
    readonly namespace: ColumnKey<Identifier>;
    readonly value: ColumnKey<Identifier>;
    /** Evaluate the consumer's explicit current-ownership/availability semantics. */
    readonly isCurrent: (
      input: ProofAuthorityInput<NativeSubjectId>,
      rows: ReadonlyArray<InferSelectModel<Identifier>>,
    ) => boolean;
    /** Optional outside D1. Never infer this semantic predicate from eligibility. */
    readonly d1CurrentCondition?: (input: ProofAuthorityInput<NativeSubjectId>) => SQL;
  };
  readonly subject?: {
    readonly table: Subject;
    readonly id: ColumnKey<Subject>;
    readonly status: ColumnKey<Subject>;
    readonly securityRevision: ColumnKey<Subject>;
    readonly isActiveStatus: (value: unknown) => boolean;
    readonly d1ActiveStatusValue: unknown;
  };
  readonly credential?: {
    readonly table: Credential;
    readonly subjectId: ColumnKey<Credential>;
    readonly credentialId: ColumnKey<Credential>;
    readonly revision: ColumnKey<Credential>;
    readonly status?: ColumnKey<Credential>;
    readonly isActiveStatus?: (value: unknown) => boolean;
    readonly d1ActiveStatusValue?: unknown;
  };
  readonly subjectId?: SubjectIdCodec<NativeSubjectId>;
}

export interface ProofRequestTable<Request extends Table> {
  readonly table: Request;
  readonly moduleId: ColumnKey<Request>;
  readonly requestId: ColumnKey<Request>;
  readonly fingerprint: ColumnKey<Request>;
  readonly proofId: ColumnKey<Request>;
  readonly purpose: ColumnKey<Request>;
  readonly keyId: ColumnKey<Request>;
  readonly createdAt: ColumnKey<Request>;
  readonly retentionUntil: ColumnKey<Request>;
  readonly encodeInsert: (input: {
    readonly record: ProofRecord;
    readonly createdAtMillis: number;
    readonly retentionUntilMillis: number;
  }) => InferInsertModel<Request>;
  readonly decodeReceipt: (
    row: InferSelectModel<Request>,
  ) => Effect.Effect<ProofRequestReceipt, PersistenceMappingError>;
}

export interface ProofSeriesTable<Series extends Table> {
  readonly table: Series;
  readonly moduleId: ColumnKey<Series>;
  readonly purpose: ColumnKey<Series>;
  readonly scopeKey: ColumnKey<Series>;
  readonly activeProofId: ColumnKey<Series>;
  readonly lastIssueAt: ColumnKey<Series>;
  readonly version: ColumnKey<Series>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly scopeKey: string;
    readonly version: ProofVersion;
  }) => InferInsertModel<Series>;
}

export interface ProofGenerationTable<Generation extends Table> {
  readonly table: Generation;
  readonly moduleId: ColumnKey<Generation>;
  readonly purpose: ColumnKey<Generation>;
  readonly proofId: ColumnKey<Generation>;
  readonly requestId: ColumnKey<Generation>;
  readonly seriesKey: ColumnKey<Generation>;
  readonly deliveryId: ColumnKey<Generation>;
  readonly binding: ColumnKey<Generation>;
  readonly verifierKeyId: ColumnKey<Generation>;
  readonly verifierDigest: ColumnKey<Generation>;
  readonly issuedAt: ColumnKey<Generation>;
  readonly expiresAt: ColumnKey<Generation>;
  readonly version: ColumnKey<Generation>;
  readonly state: ColumnKey<Generation>;
  readonly sendCount: ColumnKey<Generation>;
  readonly deliveryState: ColumnKey<Generation>;
  readonly claimVersion: ColumnKey<Generation>;
  readonly claimDeadline: ColumnKey<Generation>;
  readonly retryAt: ColumnKey<Generation>;
  readonly deliveryRetryMillis: ColumnKey<Generation>;
  readonly retentionUntil: ColumnKey<Generation>;
  readonly encodeInsert: (input: {
    readonly record: ProofRecord;
    readonly seriesKey: string;
    readonly retentionUntilMillis: number;
    readonly state: ProofGenerationState;
    readonly deliveryState: ProofDeliveryState;
    readonly policy: ProofPolicy;
  }) => InferInsertModel<Generation>;
  readonly decodeRecord: (
    row: InferSelectModel<Generation>,
  ) => Effect.Effect<ProofRecord, PersistenceMappingError>;
  readonly decodeBinding: (
    row: InferSelectModel<Generation>,
  ) => Effect.Effect<ProofBinding, PersistenceMappingError>;
}

export interface ProofContinuationRecord {
  readonly moduleId: string;
  readonly purpose: ProofPurpose;
  readonly continuationId: ProofContinuationId;
  readonly digest: TokenDigest;
  readonly proofId: ProofId;
  readonly seriesKey: string;
  readonly binding: ProofBinding;
  readonly expiresAtMillis: number;
  readonly version: ProofVersion;
}

export interface ProofContinuationTable<Continuation extends Table> {
  readonly table: Continuation;
  readonly moduleId: ColumnKey<Continuation>;
  readonly purpose: ColumnKey<Continuation>;
  readonly continuationId: ColumnKey<Continuation>;
  readonly digest: ColumnKey<Continuation>;
  readonly proofId: ColumnKey<Continuation>;
  readonly seriesKey: ColumnKey<Continuation>;
  readonly binding: ColumnKey<Continuation>;
  readonly expiresAt: ColumnKey<Continuation>;
  readonly consumed: ColumnKey<Continuation>;
  readonly version: ColumnKey<Continuation>;
  readonly retentionUntil: ColumnKey<Continuation>;
  readonly encodeInsert: (
    record: ProofContinuationRecord & { readonly retentionUntilMillis: number },
  ) => InferInsertModel<Continuation>;
  readonly decode: (
    row: InferSelectModel<Continuation>,
  ) => Effect.Effect<ProofContinuationRecord, PersistenceMappingError>;
}

export interface ProofRateScopeTable<RateScope extends Table> {
  readonly table: RateScope;
  readonly moduleId: ColumnKey<RateScope>;
  readonly purpose: ColumnKey<RateScope>;
  readonly action: ColumnKey<RateScope>;
  readonly scopeKind: ColumnKey<RateScope>;
  readonly scopeKey: ColumnKey<RateScope>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly action: ProofAction;
    readonly scopeKind: ProofScopeKind;
    readonly scopeKey: string;
  }) => InferInsertModel<RateScope>;
}

export interface ProofAbuseEventTable<AbuseEvent extends Table> {
  readonly table: AbuseEvent;
  readonly moduleId: ColumnKey<AbuseEvent>;
  readonly purpose: ColumnKey<AbuseEvent>;
  readonly action: ColumnKey<AbuseEvent>;
  readonly scopeKind: ColumnKey<AbuseEvent>;
  readonly scopeKey: ColumnKey<AbuseEvent>;
  readonly commandId: ColumnKey<AbuseEvent>;
  readonly occurredAt: ColumnKey<AbuseEvent>;
  readonly retentionUntil: ColumnKey<AbuseEvent>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly action: ProofAction;
    readonly scopeKind: ProofScopeKind;
    readonly scopeKey: string;
    readonly commandId: string;
    readonly occurredAtMillis: number;
    readonly retentionUntilMillis: number;
  }) => InferInsertModel<AbuseEvent>;
}

export interface ProofFailureEventTable<FailureEvent extends Table> {
  readonly table: FailureEvent;
  readonly moduleId: ColumnKey<FailureEvent>;
  readonly purpose: ColumnKey<FailureEvent>;
  readonly seriesKey: ColumnKey<FailureEvent>;
  readonly commandId: ColumnKey<FailureEvent>;
  readonly occurredAt: ColumnKey<FailureEvent>;
  readonly retentionUntil: ColumnKey<FailureEvent>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly seriesKey: string;
    readonly commandId: string;
    readonly occurredAtMillis: number;
    readonly retentionUntilMillis: number;
  }) => InferInsertModel<FailureEvent>;
}

export interface ProofCommandTable<Command extends Table> {
  readonly table: Command;
  readonly moduleId: ColumnKey<Command>;
  readonly commandId: ColumnKey<Command>;
  readonly kind: ColumnKey<Command>;
  readonly decision: ColumnKey<Command>;
  readonly retentionUntil: ColumnKey<Command>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly commandId: string;
    readonly kind: ProofCommandKind;
    readonly decision: ProofCommandDecision;
    readonly retentionUntilMillis: number;
  }) => InferInsertModel<Command>;
}

export interface RequiredProofConstraints {
  readonly request: "unique(request.moduleId,request.requestId)";
  readonly series: "unique(series.moduleId,series.purpose,series.scopeKey)";
  readonly proof: "unique(generation.moduleId,generation.proofId)";
  readonly delivery: "unique(generation.moduleId,generation.deliveryId)";
  readonly continuationId: "unique(continuation.moduleId,continuation.continuationId)";
  readonly continuationDigest: "unique(continuation.moduleId,continuation.digest)";
  readonly rateScope: "unique(rateScope.moduleId,rateScope.purpose,rateScope.action,rateScope.scopeKind,rateScope.scopeKey)";
  readonly abuseEvent: "unique(abuseEvent.moduleId,abuseEvent.action,abuseEvent.scopeKind,abuseEvent.scopeKey,abuseEvent.commandId)";
  readonly failureEvent: "unique(failureEvent.moduleId,failureEvent.seriesKey,failureEvent.commandId)";
  readonly command: "unique(command.moduleId,command.commandId)";
}

export const requiredProofConstraints: RequiredProofConstraints = {
  request: "unique(request.moduleId,request.requestId)",
  series: "unique(series.moduleId,series.purpose,series.scopeKey)",
  proof: "unique(generation.moduleId,generation.proofId)",
  delivery: "unique(generation.moduleId,generation.deliveryId)",
  continuationId: "unique(continuation.moduleId,continuation.continuationId)",
  continuationDigest: "unique(continuation.moduleId,continuation.digest)",
  rateScope:
    "unique(rateScope.moduleId,rateScope.purpose,rateScope.action,rateScope.scopeKind,rateScope.scopeKey)",
  abuseEvent:
    "unique(abuseEvent.moduleId,abuseEvent.action,abuseEvent.scopeKind,abuseEvent.scopeKey,abuseEvent.commandId)",
  failureEvent: "unique(failureEvent.moduleId,failureEvent.seriesKey,failureEvent.commandId)",
  command: "unique(command.moduleId,command.commandId)",
};

export interface ProofConstraintClassifier {
  /** Match only the declared request uniqueness constraint, including wrapped driver errors. */
  readonly isRequestConflict: (cause: unknown) => boolean;
  /** Match only the declared series uniqueness constraint, including wrapped driver errors. */
  readonly isSeriesConflict: (cause: unknown) => boolean;
  /** Match only the declared command uniqueness constraint, including wrapped driver errors. */
  readonly isCommandConflict: (cause: unknown) => boolean;
}

export interface ProofD1Clock {
  /** Native instant expression evaluated by SQLite inside the submitted batch. */
  readonly engineNow: SQL;
  /** Integer Unix milliseconds expression evaluated inside the submitted batch. */
  readonly engineNowMillis: SQL;
  /** Native instant expression for an engine-time rolling-window cutoff. */
  readonly engineInstantMinus: (millis: number) => SQL;
  /** Native instant expression for a retention/lease deadline from engine time. */
  readonly engineInstantPlus: (millis: number) => SQL;
}

export interface ProofPersistenceMapping<
  Request extends Table,
  Series extends Table,
  Generation extends Table,
  Continuation extends Table,
  RateScope extends Table,
  AbuseEvent extends Table,
  FailureEvent extends Table,
  Command extends Table,
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> extends ProofConstraintClassifier {
  readonly request: ProofRequestTable<Request>;
  readonly series: ProofSeriesTable<Series>;
  readonly generation: ProofGenerationTable<Generation>;
  readonly continuation: ProofContinuationTable<Continuation>;
  readonly rateScope: ProofRateScopeTable<RateScope>;
  readonly abuseEvent: ProofAbuseEventTable<AbuseEvent>;
  readonly failureEvent: ProofFailureEventTable<FailureEvent>;
  readonly command: ProofCommandTable<Command>;
  readonly authority: ProofAuthorityTables<Subject, Identifier, Credential, NativeSubjectId>;
  readonly constraints: RequiredProofConstraints;
  readonly scopeKeys: (input: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly binding: ProofBinding;
  }) => ProofScopeKeys;
  readonly encodeInstant: (epochMillis: number) => unknown;
  readonly decodeInstant: (native: unknown) => Effect.Effect<number, PersistenceMappingError>;
  readonly allocateVersion?: Effect.Effect<ProofVersion, PersistenceMappingError>;
  readonly allocateVersionSync?: () => ProofVersion;
  /** Required by D1 mappings and ignored by interactive targets. */
  readonly d1?: ProofD1Clock;
}

export type D1ProofPersistenceMapping<
  Request extends Table,
  Series extends Table,
  Generation extends Table,
  Continuation extends Table,
  RateScope extends Table,
  AbuseEvent extends Table,
  FailureEvent extends Table,
  Command extends Table,
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> = ProofPersistenceMapping<
  Request,
  Series,
  Generation,
  Continuation,
  RateScope,
  AbuseEvent,
  FailureEvent,
  Command,
  Subject,
  Identifier,
  Credential,
  NativeSubjectId
> & {
  readonly d1: ProofD1Clock;
  readonly authority: ProofAuthorityTables<Subject, Identifier, Credential, NativeSubjectId> & {
    readonly identifier: ProofAuthorityTables<
      Subject,
      Identifier,
      Credential,
      NativeSubjectId
    >["identifier"] & {
      /** Synchronous SQL compiler; Effect-based ID conversion has already completed. */
      readonly d1CurrentCondition: (input: ProofAuthorityInput<NativeSubjectId>) => SQL;
    };
  };
};

export type AnyProofPersistenceMapping = ProofPersistenceMapping<
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  unknown
>;
