import type { SubjectId, TokenDigest } from "@yielded/auth/Schema";
import type {
  AuthenticationEvidence,
  AuthenticationRequirement,
  PendingAuthenticationRecord,
  PendingConsumption,
  SecurityRevision,
  SessionUnavailable,
  SessionId,
  StatefulSessionPersistence,
  StatefulSessionRecord,
} from "@yielded/auth/Sessions";
import type { DateTime, Effect } from "effect";

import type { PersistenceMappingError } from "./mapping-error";
import type { PersistenceOwner, PersistenceStoreError } from "./persistence-owner";

/** The authority belongs to the decoded session owner. Adapters must retain a
 * transactional decoded-owner lookup when their physical join cannot prove it. */
export interface SessionVerificationRead<Claims> {
  readonly record: StatefulSessionRecord<Claims>;
  readonly authority:
    | {
        readonly active: boolean;
        readonly securityRevision: SecurityRevision;
      }
    | undefined;
}

export interface SessionVerificationReader<Claims> {
  readonly readForVerification: (
    digest: TokenDigest,
  ) => Effect.Effect<SessionVerificationRead<Claims> | undefined, PersistenceStoreError>;
}

export interface SessionSubjectAuthority {
  readonly active: boolean;
  readonly securityRevision: SecurityRevision;
  readonly requirement: Effect.Effect<AuthenticationRequirement, PersistenceStoreError>;
}

export interface SessionFlowRead {
  readonly pending: boolean;
  readonly pendingDigest: TokenDigest | undefined;
  readonly dedupUntil: DateTime.Utc;
}

export interface SessionAuthorityRead {
  readonly subject: SessionSubjectAuthority | undefined;
  readonly credentials: ReadonlyArray<{
    readonly credentialId: string;
    readonly revision: SecurityRevision;
    readonly active: boolean;
  }>;
  readonly flow: SessionFlowRead | undefined;
}

export interface SessionAuthorityReader {
  /** Lock subject, then credentials in ID order, then the optional flow. An
   * unlocked read observes one snapshot, including custom mapping decoders. */
  readonly readAuthority: (
    subjectId: SubjectId,
    credentialIds: ReadonlyArray<string>,
    locking: boolean,
    flowId?: string,
  ) => Effect.Effect<SessionAuthorityRead, PersistenceStoreError>;
}

export interface SessionPendingRead<Claims> {
  readonly record: PendingAuthenticationRecord<Claims>;
  readonly failedAttempts: number;
  readonly consumed: boolean;
  readonly flow: SessionFlowRead | undefined;
}

export interface SessionPendingStore<Claims> {
  readonly lockPending: (
    digest: TokenDigest,
  ) => Effect.Effect<SessionPendingRead<Claims> | undefined, PersistenceStoreError>;
  readonly consumePending: (
    input: PendingConsumption,
    dedupUntil: DateTime.Utc,
  ) => Effect.Effect<void, PersistenceStoreError>;
}

export interface SessionAuthorityStore<Claims> extends SessionAuthorityReader {
  readonly pending?: SessionPendingStore<Claims>;
}

export interface StatefulSessionStore<Claims>
  extends SessionVerificationReader<Claims>, SessionAuthorityStore<Claims> {
  readonly readSubject: (
    subjectId: SubjectId,
    locking: boolean,
  ) => Effect.Effect<SessionSubjectAuthority | undefined, PersistenceStoreError>;
  /** Discover the decoded owner, lock it, then lock and decode the session. */
  readonly lockRotation: (
    sessionId: SessionId,
  ) => Effect.Effect<SessionVerificationRead<Claims> | undefined, PersistenceStoreError>;
  /** Discover the decoded owner, lock it, then test the locked digest row. */
  readonly lockDigest: (digest: TokenDigest) => Effect.Effect<boolean, PersistenceStoreError>;
  readonly establish: (
    record: StatefulSessionRecord<Claims>,
    evidence: AuthenticationEvidence,
    pending: PendingConsumption | undefined,
    replaceFlow: boolean,
    /** Preserve the allocated native identity; arbitrary codecs need not
     * round-trip a noncanonical stored representation. */
    nativeSessionId: unknown,
  ) => Effect.Effect<void, PersistenceStoreError>;
  readonly rotate: (
    input: Parameters<StatefulSessionPersistence<Claims>["rotate"]>[0],
    next: StatefulSessionRecord<Claims>,
  ) => Effect.Effect<void, PersistenceStoreError>;
  readonly revokeDigest: (digest: TokenDigest) => Effect.Effect<void, PersistenceStoreError>;
  readonly revoke: (
    input: Parameters<StatefulSessionPersistence<Claims>["revoke"]>[0],
  ) => Effect.Effect<void, PersistenceStoreError>;
  readonly revokeAll: (
    input: Parameters<StatefulSessionPersistence<Claims>["revokeAll"]>[0],
    nextRevision: SecurityRevision,
  ) => Effect.Effect<void, PersistenceStoreError>;
  readonly readPage: (input: {
    readonly subjectId: SubjectId;
    readonly securityRevision: SecurityRevision;
    readonly now: DateTime.Utc;
    readonly cursor?: string;
    readonly limit: number;
  }) => Effect.Effect<ReadonlyArray<StatefulSessionRecord<Claims>>, PersistenceStoreError>;
}

export interface SessionSqlOptions {
  readonly coordinated?: boolean;
  readonly mode: "interactive" | "synchronous";
  readonly locking: boolean;
  /** Reject an ambient foreign owner before IDs or writes. */
  readonly standaloneGuard: Effect.Effect<void, SessionUnavailable>;
}

export interface SessionTransactionOwner<Operations> extends PersistenceOwner<Operations> {
  readonly isCurrent: Effect.Effect<boolean>;
}

/** Allocation and conflict policy used by the shared workflow. Native table
 * mappings stay in the backend; the original allocated identity is retained. */
export interface SessionWorkflowPolicy<NativeSessionId> {
  readonly isConstraintConflict: (cause: unknown) => boolean;
  readonly session: {
    readonly allocateId?: Effect.Effect<NativeSessionId, PersistenceMappingError>;
    readonly allocateIdSync?: () => NativeSessionId;
    readonly allocateVersion?: Effect.Effect<SecurityRevision, PersistenceMappingError>;
    readonly allocateVersionSync?: () => SecurityRevision;
  };
  readonly sessionId: {
    readonly toSession: (id: NativeSessionId) => Effect.Effect<SessionId, PersistenceMappingError>;
  };
  readonly subject: {
    readonly nextSecurityRevision?: (
      current: SecurityRevision,
    ) => Effect.Effect<SecurityRevision, PersistenceMappingError>;
    readonly nextSecurityRevisionSync?: (current: SecurityRevision) => SecurityRevision;
  };
}
