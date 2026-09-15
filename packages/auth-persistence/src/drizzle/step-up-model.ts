import type { SecurityRevision, SessionStepUpIntent } from "@yielded/auth/Sessions";
import type { InferInsertModel, Table } from "drizzle-orm";
import type { DateTime, Effect } from "effect";

import type { PersistenceMappingError } from "./model";
import type {
  D1SessionClockMapping,
  SessionAuthorityTables,
  SessionConstraintClassifier,
  SessionIdCodec,
  SignedSessionValidityTables,
  StatefulSessionTables,
} from "./session-model";

type ColumnKey<T extends Table> = Extract<keyof T["_"]["columns"], string>;

/** Distinct from login-pending storage. Snapshot is TEXT encoded by the core's
 * SessionStepUpIntent schema; it contains no Claims and needs no consumer decoder. */
export interface SessionStepUpIntentTables<Intent extends Table, NativeSubjectId> {
  readonly intent: {
    readonly table: Intent;
    readonly digest: ColumnKey<Intent>;
    readonly version: ColumnKey<Intent>;
    readonly flowId: ColumnKey<Intent>;
    readonly subjectId: ColumnKey<Intent>;
    readonly bindingDigest: ColumnKey<Intent>;
    readonly snapshot: ColumnKey<Intent>;
    readonly expiresAt: ColumnKey<Intent>;
    readonly attemptLimit: ColumnKey<Intent>;
    readonly failedAttempts: ColumnKey<Intent>;
    readonly consumed: ColumnKey<Intent>;
    readonly encodeInstant: (instant: DateTime.Utc) => unknown;
    /** Consumer fields/defaults; the adapter sets all mapped security columns. */
    readonly encodeInsert: (
      intent: SessionStepUpIntent,
      input: { readonly subjectId: NativeSubjectId },
    ) => InferInsertModel<Intent>;
    readonly allocateVersion?: Effect.Effect<SecurityRevision, PersistenceMappingError>;
    readonly allocateVersionSync?: () => SecurityRevision;
  };
}

export interface RequiredSessionStepUpConstraints {
  readonly intentDigest: "unique(intent.digest)";
  readonly intentFlow: "unique(intent.flowId)";
}

export const requiredSessionStepUpConstraints: RequiredSessionStepUpConstraints = {
  intentDigest: "unique(intent.digest)",
  intentFlow: "unique(intent.flowId)",
};

/** Fixed source discriminator is checked against every stored intent. A minimal
 * pure-signed installation does not provide dummy session or tombstone tables. */
export type SessionStepUpSourceTables<
  Claims,
  Session extends Table,
  Tombstone extends Table,
  NativeSubjectId,
  NativeSessionId,
> =
  | { readonly kind: "StatelessSigned" }
  | ({
      readonly kind: "StateAssistedSigned";
      readonly constraints: {
        readonly tombstoneOwner: "unique(tombstone.subjectId,tombstone.sessionId)";
      };
    } & SignedSessionValidityTables<Tombstone, NativeSubjectId, NativeSessionId>)
  | {
      readonly kind: "Stateful";
      readonly constraints: { readonly sessionDigest: "unique(session.digest)" };
      readonly sessionId: SessionIdCodec<NativeSessionId>;
      readonly session: StatefulSessionTables<
        Claims,
        Session,
        Table,
        NativeSubjectId,
        NativeSessionId
      >["session"] & {
        readonly credentialVersion: ColumnKey<Session>;
        readonly authenticatedAt: ColumnKey<Session>;
        /** encodeRotation must persist the full replacement Claims/provenance and
         * these queryable security fields, never preserve the old proof payload. */
      };
    };

export type SessionStepUpMapping<
  Claims,
  Subject extends Table,
  Credential extends Table,
  Intent extends Table,
  Session extends Table,
  Tombstone extends Table,
  NativeSubjectId,
  NativeSessionId,
> = SessionAuthorityTables<Subject, Credential, NativeSubjectId> &
  SessionStepUpIntentTables<Intent, NativeSubjectId> &
  SessionConstraintClassifier & {
    readonly source: SessionStepUpSourceTables<
      Claims,
      Session,
      Tombstone,
      NativeSubjectId,
      NativeSessionId
    >;
    readonly constraints: RequiredSessionStepUpConstraints;
  };

export type D1SessionStepUpMapping<
  Claims,
  Subject extends Table,
  Credential extends Table,
  Intent extends Table,
  Session extends Table,
  Tombstone extends Table,
  NativeSubjectId,
  NativeSessionId,
> = SessionStepUpMapping<
  Claims,
  Subject,
  Credential,
  Intent,
  Session,
  Tombstone,
  NativeSubjectId,
  NativeSessionId
> &
  D1SessionClockMapping;
