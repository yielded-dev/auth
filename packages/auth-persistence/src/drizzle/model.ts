import { AuthStore } from "@yielded/auth/AuthStore";
import { AuthStoreError } from "@yielded/auth/Errors";
import {
  ExternalIdentityMutation,
  SubjectProvisioner,
  type SubjectProvisioningInput,
  type ExternalIdentity,
  type LoginIdentifier,
} from "@yielded/auth/Identity";
import { OAuthStateStore, type OAuthState } from "@yielded/auth/OAuth";
import {
  type ConsumeChallenge,
  type NewChallenge,
  type NewRegistration,
  type PendingRegistration,
  type SubjectId,
} from "@yielded/auth/Schema";
import {
  getTableColumns,
  type AnyColumn,
  type InferInsertModel,
  type InferSelectModel,
  type Table,
} from "drizzle-orm";
import { Context, DateTime, Effect, Layer, Option } from "effect";
import type * as SqlClient from "effect/unstable/sql/SqlClient";

export type CommitMode = "interactive" | "synchronous" | "batch";

/**
 * Ordinary error-channel consumes must own their commit. Coordinated callers
 * use the decision methods inside their outer transaction and translate only
 * after that owner commits.
 */
export interface SqlClientTransactionDatabase {
  readonly $client: Pick<SqlClient.SqlClient, "transactionService">;
}

export const requireStandaloneConsume = (
  database: SqlClientTransactionDatabase,
): Effect.Effect<void, AuthStoreError> =>
  Effect.serviceOption(database.$client.transactionService).pipe(
    Effect.flatMap(
      Option.match({
        onNone: () => Effect.void,
        onSome: () =>
          AuthStoreError.make({
            message: "Use the decision consume API inside an outer database transaction",
          }),
      }),
    ),
  );

export type { ChallengeConsumeDecision } from "@yielded/auth/Persistence";
export type { ConsumeDecision } from "@yielded/auth/AuthStore";

export { PersistenceMappingError, isMappedConstraintConflict } from "../internal/mapping-error";
import type { PersistenceMappingError } from "../internal/mapping-error";

export interface InstantCodec<NativeInstant> {
  readonly encode: (instant: DateTime.Utc) => NativeInstant;
  readonly decode: (native: NativeInstant) => Effect.Effect<DateTime.Utc, PersistenceMappingError>;
}

export interface RequiredAuthStoreConstraints {
  readonly series: "unique(namespace,value,purpose)";
  readonly challengeDigest: "unique(tokenDigest)";
  readonly registrationDigest: "unique(tokenDigest)";
}

export interface RequiredOAuthStateConstraints {
  readonly oauthStateDigest: "unique(stateDigest)";
}

export interface RequiredAuthConstraints
  extends RequiredAuthStoreConstraints, RequiredOAuthStateConstraints {}

export const requiredAuthConstraints: RequiredAuthConstraints = {
  series: "unique(namespace,value,purpose)",
  challengeDigest: "unique(tokenDigest)",
  registrationDigest: "unique(tokenDigest)",
  oauthStateDigest: "unique(stateDigest)",
};

export const requiredAuthStoreConstraints: RequiredAuthStoreConstraints = {
  series: "unique(namespace,value,purpose)",
  challengeDigest: "unique(tokenDigest)",
  registrationDigest: "unique(tokenDigest)",
};

export const requiredOAuthStateConstraints: RequiredOAuthStateConstraints = {
  oauthStateDigest: "unique(stateDigest)",
};

type ColumnKey<T extends Table> = Extract<keyof T["_"]["columns"], string>;

export interface ChallengeRecord {
  readonly challenge: NewChallenge;
  readonly namespace: string;
  readonly failedAttempts: number;
  readonly consumed: boolean;
}

export interface ChallengeColumns<T extends Table> {
  readonly challengeId: ColumnKey<T>;
  readonly tokenDigest: ColumnKey<T>;
  readonly namespace: ColumnKey<T>;
  readonly value: ColumnKey<T>;
  readonly purpose: ColumnKey<T>;
  readonly otpKeyId: ColumnKey<T>;
  readonly otpDigest: ColumnKey<T>;
  readonly issuedAt: ColumnKey<T>;
  readonly expiresAt: ColumnKey<T>;
  readonly attemptLimit: ColumnKey<T>;
  readonly failedAttempts: ColumnKey<T>;
  readonly consumed: ColumnKey<T>;
}

/**
 * Inputs are immutable server-created issuances. Replacements must advance
 * issuedAt; equal or older issuances fail even after consumption or expiry.
 * Instant encoding must preserve this ordering. Retain the series row as an
 * issuance watermark until every previously accepted issuance has expired;
 * current-row expiry alone is insufficient if historical lifetimes were longer.
 */
export interface ChallengeTableMapping<T extends Table> {
  readonly table: T;
  readonly columns: ChallengeColumns<T>;
  readonly identifierNamespace: string;
  readonly encodeInstant: (instant: DateTime.Utc) => unknown;
  readonly encodeInsert: (
    input: NewChallenge,
    state: {
      readonly namespace: string;
      readonly failedAttempts: number;
      readonly consumed: false;
    },
  ) => InferInsertModel<T>;
  readonly encodeUpdate: (
    input: NewChallenge,
    state: {
      readonly namespace: string;
      readonly failedAttempts: unknown;
      readonly consumed: false;
    },
  ) => Readonly<Record<string, unknown>>;
  readonly decode: (
    row: InferSelectModel<T>,
  ) => Effect.Effect<ChallengeRecord, PersistenceMappingError>;
}

export interface RegistrationRecord {
  readonly registration: PendingRegistration;
  readonly consumed: boolean;
}

export interface RegistrationColumns<T extends Table> {
  readonly registrationId: ColumnKey<T>;
  readonly tokenDigest: ColumnKey<T>;
  readonly expiresAt: ColumnKey<T>;
  readonly consumed: ColumnKey<T>;
}

export interface RegistrationTableMapping<T extends Table> {
  readonly table: T;
  readonly columns: RegistrationColumns<T>;
  readonly encodeInstant: (instant: DateTime.Utc) => unknown;
  readonly encodeInsert: (input: NewRegistration, consumed: false) => InferInsertModel<T>;
  readonly decode: (
    row: InferSelectModel<T>,
  ) => Effect.Effect<RegistrationRecord, PersistenceMappingError>;
}

export interface OAuthStateColumns<T extends Table> {
  readonly stateDigest: ColumnKey<T>;
  readonly expiresAt: ColumnKey<T>;
  readonly consumed: ColumnKey<T>;
}

export interface OAuthStateTableMapping<T extends Table> {
  readonly table: T;
  readonly columns: OAuthStateColumns<T>;
  readonly encodeInstant: (instant: DateTime.Utc) => unknown;
  readonly encodeInsert: (state: OAuthState, consumed: false) => InferInsertModel<T>;
  readonly decode: (
    row: InferSelectModel<T>,
  ) => Effect.Effect<
    { readonly state: OAuthState; readonly consumed: boolean },
    PersistenceMappingError
  >;
}

export interface AuthStoreTables<Challenge extends Table, Registration extends Table> {
  readonly constraints: RequiredAuthStoreConstraints;
  readonly challenge: ChallengeTableMapping<Challenge>;
  readonly registration: RegistrationTableMapping<Registration>;
}

export interface OAuthStateTables<State extends Table> {
  readonly constraints: RequiredOAuthStateConstraints;
  readonly oauthState: OAuthStateTableMapping<State>;
}

export interface AuthTables<
  Challenge extends Table,
  Registration extends Table,
  State extends Table,
> {
  readonly constraints: RequiredAuthConstraints;
  readonly challenge: ChallengeTableMapping<Challenge>;
  readonly registration: RegistrationTableMapping<Registration>;
  readonly oauthState: OAuthStateTableMapping<State>;
}

export interface RequiredIdentityConstraints {
  readonly identifier: "unique(namespace,value)";
  readonly externalIdentity: "unique(provider,issuer,subject)";
  readonly provisioningRequest: "unique(requestId)";
  readonly provisioningSubject: "notNull(provisioningRequest.subjectId)";
}

export interface RequiredSubjectProvisioningConstraints {
  readonly identifier: "unique(namespace,value)";
  readonly provisioningRequest: "unique(requestId)";
  readonly provisioningSubject: "notNull(provisioningRequest.subjectId)";
}

export interface RequiredExternalIdentityConstraints {
  readonly externalIdentity: "unique(provider,issuer,subject)";
}

export const requiredIdentityConstraints: RequiredIdentityConstraints = {
  identifier: "unique(namespace,value)",
  externalIdentity: "unique(provider,issuer,subject)",
  provisioningRequest: "unique(requestId)",
  provisioningSubject: "notNull(provisioningRequest.subjectId)",
};

export const requiredSubjectProvisioningConstraints: RequiredSubjectProvisioningConstraints = {
  identifier: "unique(namespace,value)",
  provisioningRequest: "unique(requestId)",
  provisioningSubject: "notNull(provisioningRequest.subjectId)",
};

export const requiredExternalIdentityConstraints: RequiredExternalIdentityConstraints = {
  externalIdentity: "unique(provider,issuer,subject)",
};

export interface SubjectIdCodec<NativeId> {
  readonly toNative: (id: SubjectId) => Effect.Effect<NativeId, PersistenceMappingError>;
  readonly toSubject: (id: NativeId) => Effect.Effect<SubjectId, PersistenceMappingError>;
  readonly equals: (left: NativeId, right: NativeId) => boolean;
}

export interface SubjectProvisioningTables<
  Subject extends Table,
  Identifier extends Table,
  Request extends Table,
  NativeId,
> {
  readonly constraints: RequiredSubjectProvisioningConstraints;
  readonly subject: {
    readonly table: Subject;
    readonly id: ColumnKey<Subject>;
    readonly status: ColumnKey<Subject>;
    readonly isActiveStatus: (value: unknown) => boolean;
    readonly encodeInsert: (
      input: SubjectProvisioningInput,
      allocatedId: NativeId | undefined,
    ) => InferInsertModel<Subject>;
    readonly allocateId?: Effect.Effect<NativeId, PersistenceMappingError>;
    /** Required instead of allocateId when a synchronous-only DO transaction preallocates IDs. */
    readonly allocateIdSync?: () => NativeId;
    /** Decodes MySQL `$returningId()` for an autoincrement/runtime-default key. */
    readonly decodeGeneratedId?: (
      rows: ReadonlyArray<unknown>,
    ) => Effect.Effect<NativeId, PersistenceMappingError>;
  };
  readonly identifier: {
    readonly table: Identifier;
    readonly namespace: ColumnKey<Identifier>;
    readonly value: ColumnKey<Identifier>;
    readonly subjectId: ColumnKey<Identifier>;
    readonly encodeInsert: (
      identifier: LoginIdentifier,
      subjectId: NativeId,
      verifiedAt: DateTime.Utc | undefined,
    ) => InferInsertModel<Identifier>;
  };
  readonly provisioningRequest: {
    readonly table: Request;
    readonly requestId: ColumnKey<Request>;
    readonly fingerprint: ColumnKey<Request>;
    readonly subjectId: ColumnKey<Request>;
    readonly encodeInsert: (
      requestId: string,
      fingerprint: string,
      subjectId: NativeId,
    ) => InferInsertModel<Request>;
  };
  readonly subjectId: SubjectIdCodec<NativeId>;
  /** Narrows only database constraint failures; every other cause is unavailable. */
  readonly isConstraintConflict: (cause: unknown) => boolean;
}

export interface ExternalIdentityTables<Subject extends Table, External extends Table, NativeId> {
  readonly constraints: RequiredExternalIdentityConstraints;
  readonly subject: {
    readonly table: Subject;
    readonly id: ColumnKey<Subject>;
    readonly status: ColumnKey<Subject>;
    readonly isActiveStatus: (value: unknown) => boolean;
  };
  readonly externalIdentity: {
    readonly table: External;
    readonly provider: ColumnKey<External>;
    readonly issuer: ColumnKey<External>;
    readonly subject: ColumnKey<External>;
    readonly subjectId: ColumnKey<External>;
    readonly encodeInsert: (
      identity: ExternalIdentity,
      subjectId: NativeId,
    ) => InferInsertModel<External>;
  };
  readonly subjectId: SubjectIdCodec<NativeId>;
  readonly isConstraintConflict: (cause: unknown) => boolean;
}

export interface IdentityTables<
  Subject extends Table,
  Identifier extends Table,
  External extends Table,
  Request extends Table,
  NativeId,
> {
  readonly constraints: RequiredIdentityConstraints;
  readonly subject: SubjectProvisioningTables<Subject, Identifier, Request, NativeId>["subject"];
  readonly identifier: SubjectProvisioningTables<
    Subject,
    Identifier,
    Request,
    NativeId
  >["identifier"];
  readonly externalIdentity: ExternalIdentityTables<
    Subject,
    External,
    NativeId
  >["externalIdentity"];
  readonly provisioningRequest: SubjectProvisioningTables<
    Subject,
    Identifier,
    Request,
    NativeId
  >["provisioningRequest"];
  readonly subjectId: SubjectIdCodec<NativeId>;
  readonly isConstraintConflict: (cause: unknown) => boolean;
}

/** Extra encoders used by D1's ordered batch when the subject id is database-generated. */
export interface D1SubjectProvisioningMapping<
  Subject extends Table,
  Identifier extends Table,
  Request extends Table,
  NativeId,
> extends SubjectProvisioningTables<Subject, Identifier, Request, NativeId> {
  readonly d1: {
    readonly requestInsertWithoutSubject: (
      requestId: string,
      fingerprint: string,
    ) => Partial<InferInsertModel<Request>>;
    readonly identifierInsertWithoutSubject: (
      identifier: LoginIdentifier,
      verifiedAt: DateTime.Utc | undefined,
    ) => Partial<InferInsertModel<Identifier>>;
    /** Unshadowed hidden-rowid alias; omit for WITHOUT ROWID or preallocated IDs. */
    readonly generatedRowIdAlias?: "rowid" | "_rowid_" | "oid";
  };
}

export interface D1ExternalIdentityMapping<
  Subject extends Table,
  External extends Table,
  NativeId,
> extends ExternalIdentityTables<Subject, External, NativeId> {
  readonly d1: {
    readonly activeStatusValue: unknown;
  };
}

export interface D1GeneratedIdentityMapping<
  Subject extends Table,
  Identifier extends Table,
  External extends Table,
  Request extends Table,
  NativeId,
> extends IdentityTables<Subject, Identifier, External, Request, NativeId> {
  readonly d1: D1SubjectProvisioningMapping<Subject, Identifier, Request, NativeId>["d1"] &
    D1ExternalIdentityMapping<Subject, External, NativeId>["d1"];
}

export const provisioningFingerprint = (input: SubjectProvisioningInput): string =>
  // oxlint-disable-next-line no-restricted-properties -- stable internal provisioning fingerprint, never external JSON.
  JSON.stringify(
    input.identifier === undefined
      ? ["v1", null]
      : [
          "v1",
          input.identifier.namespace,
          input.identifier.value,
          input.verifiedAt === undefined ? null : DateTime.toEpochMillis(input.verifiedAt),
        ],
  );

/**
 * Drizzle wraps Effect SQL failures before adapters observe them. Give the
 * consumer classifier each semantic wrapper in the short `cause`/`reason`
 * chain without exposing query text or bound parameters through public errors.
 */

export const column = <T extends Table>(table: T, key: ColumnKey<T>): AnyColumn =>
  getTableColumns(table)[key] as AnyColumn;

export const updateValues = <T extends Table>(
  entries: ReadonlyArray<readonly [ColumnKey<T>, unknown]>,
): Partial<InferInsertModel<T>> => Object.fromEntries(entries) as Partial<InferInsertModel<T>>;

export type ChallengeInput = ConsumeChallenge;

/** Acquire an application database in Effect and expose the auth stores as one layer. */
export const authServicesLayer = <E, R>(
  acquire: Effect.Effect<
    {
      readonly authStore: AuthStore["Service"];
      readonly oauthStateStore: OAuthStateStore["Service"];
    },
    E,
    R
  >,
) =>
  Layer.effectContext(
    Effect.map(acquire, ({ authStore, oauthStateStore }) =>
      Context.make(AuthStore, authStore).pipe(Context.add(OAuthStateStore, oauthStateStore)),
    ),
  );

/** Acquire an application database in Effect and expose the identity services as one layer. */
export const identityServicesLayer = <E, R>(
  acquire: Effect.Effect<
    {
      readonly subjectProvisioner: SubjectProvisioner["Service"];
      readonly externalIdentityMutation: ExternalIdentityMutation["Service"];
    },
    E,
    R
  >,
) =>
  Layer.effectContext(
    Effect.map(acquire, ({ subjectProvisioner, externalIdentityMutation }) =>
      Context.make(SubjectProvisioner, subjectProvisioner).pipe(
        Context.add(ExternalIdentityMutation, externalIdentityMutation),
      ),
    ),
  );
