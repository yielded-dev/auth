import type { PreparedCommit } from "@yielded/auth/Hooks";
import type {
  OAuthActionAuthorization,
  OAuthAccountRevision,
  OAuthRegistrationIntent,
  OAuthCredentialSnapshot,
  OAuthExternalIdentity,
  OAuthRegistrationAccess,
  OAuthRegistrationInspection,
  OAuthUnavailable,
  OAuthCommandId,
  PrepareOAuthCommit,
  OAuthRegistrationDecision,
  OAuthCleanupInput,
} from "@yielded/auth/OAuth";
import type { AuthenticationFactor } from "@yielded/auth/Operations";
import type { TokenDigest } from "@yielded/auth/Schema";
import type { AuthenticationRequirement, SecurityRevision } from "@yielded/auth/Sessions";
import type { Crypto, Effect, PlatformError } from "effect";

import type { TableModel as Table, SqlExpression } from "../query-operations";
import type { PersistenceMappingError, SubjectIdCodec } from "./common";

type Column<T extends Table> = T["column"];

export type OAuthFlowState =
  | "Pending"
  | "Claimed"
  | "Verified"
  | "RegistrationIssued"
  | "Linked"
  | "Cancelled"
  | "Rejected"
  | "Ambiguous"
  | "Conflict";

export type OAuthTupleState = "Unowned" | "Reserved" | "Owned";
export type OAuthRegistrationState = "Unbound" | "Registered" | "ProvisioningPending" | "Rejected";
export type OAuthAction = OAuthActionAuthorization["challenge"]["action"];

/** The engine writes every critical column explicitly after applying the pure
 * consumer encoder. Native instant values must roundtrip without precision loss. */
export interface OAuthClock<Expression extends SqlExpression = SqlExpression> {
  readonly encodeInstant: (millis: number) => unknown;
  readonly decodeInstant: (value: unknown) => number;
  /** Actual engine wall clock sampled after locks, not transaction-start time.
   * PostgreSQL uses clock_timestamp(), never now()/CURRENT_TIMESTAMP. D1 repeats
   * its primary-engine sample bounds in final guards. Return integer milliseconds. */
  readonly engineNowMillis: Expression;
}

export interface OAuthSubjectReadTable<
  S extends Table,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: S["table"];
  readonly id: Column<S>;
  readonly status: Column<S>;
  readonly securityRevision: Column<S>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly activeCondition: Expression;
}

export interface OAuthSubjectTable<
  S extends Table,
  Expression extends SqlExpression = SqlExpression,
> extends OAuthSubjectReadTable<S, Expression> {
  readonly decodeActionRequirement: (
    row: S["select"],
    action: OAuthAction,
  ) => AuthenticationRequirement;
  readonly decodeAuthenticationRequirement: (row: S["select"]) => AuthenticationRequirement;
  readonly nextSecurityRevision: (current: SecurityRevision) => SecurityRevision;
}

export interface OAuthOwnershipReadTable<
  O extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: O["table"];
  readonly identityKey: Column<O>;
  readonly provider: Column<O>;
  readonly issuer: Column<O>;
  readonly externalSubject: Column<O>;
  readonly subjectId: Column<O>;
  /** Includes Owned state when authority and ownership share a physical table. */
  readonly ownedCondition: Expression;
  readonly decodeSubjectId: (row: O["select"]) => N;
}

export interface OAuthOwnershipTable<
  O extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> extends OAuthOwnershipReadTable<O, N, Expression> {
  readonly encodeInsert: (input: {
    readonly identity: typeof OAuthExternalIdentity.Type;
    readonly identityKey: string;
    readonly subjectId: N;
  }) => O["insert"];
}

export interface OAuthCredentialReadTable<
  C extends Table,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: C["table"];
  readonly moduleId: Column<C>;
  readonly credentialId: Column<C>;
  readonly subjectId: Column<C>;
  readonly identityKey: Column<C>;
  readonly credentialRevision: Column<C>;
  readonly status: Column<C>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly activeCondition: Expression;
}

export interface OAuthCredentialTable<
  C extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> extends OAuthCredentialReadTable<C, Expression> {
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly subjectId: N;
    readonly identityKey: string;
    readonly credentialId: string;
    readonly credentialRevision: SecurityRevision;
  }) => C["insert"];
  /** This slice removes login rows. Historical records belong in separate audit storage. */
  readonly removal: "delete";
}

export interface OAuthAuthorityReadTable<
  C extends Table,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: C["table"];
  readonly subjectId: Column<C>;
  readonly credentialId: Column<C>;
  readonly revision: Column<C>;
  readonly status: Column<C>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly activeCondition: Expression;
}

export interface OAuthAuthorityTable<
  C extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> extends OAuthAuthorityReadTable<C, Expression> {
  readonly encodeInsert: (input: {
    readonly subjectId: N;
    readonly credentialId: string;
    readonly revision: SecurityRevision;
  }) => C["insert"];
}

/** Both purposes may use the same physical table. Shared tables share module/flow
 * and module/command uniqueness. The snapshot has the exact purpose-specific core
 * codec; terminal writes erase it, while identity, claim and retention columns remain. */
export interface OAuthFlowTable<F extends Table> {
  readonly table: F["table"];
  readonly moduleId: Column<F>;
  readonly flowId: Column<F>;
  readonly commandId: Column<F>;
  readonly purpose: Column<F>;
  readonly generation: Column<F>;
  readonly state: Column<F>;
  readonly version: Column<F>;
  readonly stateDigest: Column<F>;
  readonly binderVerifier: Column<F>;
  readonly binderExpiresAt: Column<F>;
  readonly snapshot: Column<F>;
  readonly issuedAt: Column<F>;
  readonly expiresAt: Column<F>;
  readonly claimId: Column<F>;
  readonly claimedAt: Column<F>;
  readonly claimExpiresAt: Column<F>;
  readonly retentionUntil: Column<F>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly flowId: string;
    readonly purpose: "sign-in" | "link";
  }) => F["insert"];
}

export interface OAuthTupleAuthorityTable<T extends Table, N> {
  readonly table: T["table"];
  readonly identityKey: Column<T>;
  readonly provider: Column<T>;
  readonly issuer: Column<T>;
  readonly externalSubject: Column<T>;
  readonly state: Column<T>;
  readonly version: Column<T>;
  readonly subjectId: Column<T>;
  /** Exact reservation identity; no application payload or bearer. */
  readonly reservation: Column<T>;
  readonly encodeInsert: (input: {
    readonly identityKey: string;
    readonly identity: typeof OAuthExternalIdentity.Type;
    readonly subjectId?: N;
  }) => T["insert"];
}

export interface OAuthRegistrationIntentTable<I extends Table> {
  readonly table: I["table"];
  readonly moduleId: Column<I>;
  readonly reference: Column<I>;
  readonly flowId: Column<I>;
  readonly claimId: Column<I>;
  readonly identityKey: Column<I>;
  readonly version: Column<I>;
  readonly state: Column<I>;
  readonly snapshot: Column<I>;
  readonly commandId: Column<I>;
  readonly fingerprint: Column<I>;
  readonly pendingReference: Column<I>;
  readonly expiresAt: Column<I>;
  readonly retentionUntil: Column<I>;
  readonly encodeInsert: (intent: OAuthRegistrationIntent) => I["insert"];
}

export interface OAuthRegistrationCommandTable<R extends Table, Registration> {
  readonly table: R["table"];
  readonly moduleId: Column<R>;
  readonly commandId: Column<R>;
  readonly reference: Column<R>;
  readonly identityKey: Column<R>;
  readonly fingerprint: Column<R>;
  readonly intentSnapshot: Column<R>;
  readonly applicationSnapshot: Column<R>;
  readonly provisioningIdentity: Column<R>;
  readonly decision: Column<R>;
  readonly retentionUntil: Column<R>;
  /** Persists exact detached Type before protected pending work can start. */
  readonly encodeInsert: (input: {
    readonly intent: OAuthRegistrationIntent;
    readonly commandId: string;
    readonly fingerprint: string;
    readonly registration: Registration;
    readonly provisioningIdentity: string;
  }) => R["insert"];
}

export interface OAuthUnlinkCommandTable<U extends Table> {
  readonly table: U["table"];
  readonly moduleId: Column<U>;
  readonly commandId: Column<U>;
  readonly subjectId: Column<U>;
  readonly credentialId: Column<U>;
  readonly intentSnapshot: Column<U>;
  readonly decision: Column<U>;
  readonly retentionUntil: Column<U>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly commandId: string;
    readonly credential: OAuthCredentialSnapshot;
  }) => U["insert"];
}

export interface OAuthEligibilityFact {
  readonly credentialId: string;
  readonly revision: SecurityRevision;
  readonly usablePrimary: boolean;
  readonly factors: ReadonlyArray<AuthenticationFactor>;
  readonly userVerified: boolean;
  readonly phishingResistant: boolean;
}

/** Each descriptor reads only its own subject-scoped method rows. The native row
 * projector and SQL condition must express the same installed method eligibility.
 * All source/identifier/policy mutations advance subject securityRevision. D1 also
 * guards exact selected IDs/versions and absence/count assumptions, never just a
 * stale boolean. An over-limit graph fails closed rather than truncating. */
export interface OAuthEligibilityTable<
  T extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: T["table"];
  readonly subjectId: Column<T>;
  readonly credentialId: Column<T>;
  readonly revision: Column<T>;
  readonly scope: string;
  readonly condition: (subjectId: N) => Expression;
  readonly decode: (row: T["select"]) => OAuthEligibilityFact | undefined;
}

/** Authenticated command replay uses current subject status and this additional
 * nonconsuming SQL policy. It never consumes a fresh action factor. */
export interface OAuthMetadataPolicy<N, Expression extends SqlExpression = SqlExpression> {
  readonly condition: (subjectId: N) => Expression;
}

export interface OAuthCleanupTable<
  T extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: T["table"];
  readonly subjectId: Column<T>;
  /** Bound to this subject's old revision; no opaque independently committing service. */
  readonly condition: (input: {
    readonly subjectId: N;
    readonly revision: OAuthAccountRevision;
    readonly removedCredentialId?: string;
  }) => Expression;
  readonly disposition: "delete";
}

export interface OAuthRegistrationEligibility<N, Expression extends SqlExpression = SqlExpression> {
  /** Pure SQL guards for mutable app policy; evaluated again after app writes. */
  readonly condition: (input: {
    readonly intent: OAuthRegistrationIntent;
    readonly nativeSubjectId?: N;
  }) => Expression;
}

export interface OAuthD1Mapping {
  readonly d1: { readonly primary: true };
}

export const requiredOAuthSignInConstraints = {
  flow: "unique(flow.moduleId,flow.flowId)",
  command: "unique(flow.moduleId,flow.commandId)",
  stateDigest: "unique(flow.stateDigest)",
  ownership: "unique(ownership.identityKey)",
  credentialId: "unique(credential.credentialId)",
  credentialIdentity: "unique(credential.identityKey)",
  authorityCredential: "unique(authority.subjectId,authority.credentialId)",
} as const;

export const requiredOAuthTupleConstraints = { identityKey: "unique(tuple.identityKey)" } as const;

export const requiredOAuthRegistrationConstraints = {
  intentReference: "unique(intent.moduleId,intent.reference)",
  intentFlow: "unique(intent.moduleId,intent.flowId)",
  command: "unique(registrationCommand.moduleId,registrationCommand.commandId)",
} as const;

export const requiredOAuthAccountsConstraints = {
  unlinkCommand: "unique(unlinkCommand.moduleId,unlinkCommand.commandId)",
} as const;

export interface OAuthSignInMapping<
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  F extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly subject: OAuthSubjectReadTable<S, Expression>;
  readonly ownership: OAuthOwnershipReadTable<O, N, Expression>;
  readonly credential: OAuthCredentialReadTable<C, Expression>;
  readonly authority: OAuthAuthorityReadTable<AC, Expression>;
  readonly flow: OAuthFlowTable<F>;
  readonly subjectId: SubjectIdCodec<N>;
  readonly clock: OAuthClock<Expression>;
  readonly constraints: typeof requiredOAuthSignInConstraints;
}

export type OAuthOwnershipMutation<
  T extends Table,
  O extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> =
  | { readonly mode: "integrated"; readonly tuple: OAuthTupleAuthorityTable<T, N> }
  | {
      readonly mode: "separate";
      readonly tuple: OAuthTupleAuthorityTable<T, N>;
      readonly external: OAuthOwnershipTable<O, N, Expression>;
    };

export interface OAuthRegistrationIntentMapping<
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  F extends Table,
  T extends Table,
  I extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly signIn: OAuthSignInMapping<S, O, C, AC, F, N, Expression>;
  readonly ownership: OAuthOwnershipMutation<T, O, N, Expression>;
  readonly intent: OAuthRegistrationIntentTable<I>;
  readonly tupleConstraints: typeof requiredOAuthTupleConstraints;
  readonly registrationConstraints: Pick<
    typeof requiredOAuthRegistrationConstraints,
    "intentReference" | "intentFlow"
  >;
  readonly eligibility: OAuthRegistrationEligibility<N, Expression>;
}

export interface OAuthRegistrationBase<
  Registration,
  T extends Table,
  O extends Table,
  I extends Table,
  R extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
  Descriptor extends object = object,
> {
  readonly ownership: OAuthOwnershipMutation<T, O, N, Expression>;
  readonly intent: OAuthRegistrationIntentTable<I>;
  readonly command: OAuthRegistrationCommandTable<R, Registration>;
  readonly clock: OAuthClock<Expression>;
  readonly tupleConstraints: typeof requiredOAuthTupleConstraints;
  readonly constraints: typeof requiredOAuthRegistrationConstraints;
  readonly inspect: (input: {
    readonly intent: OAuthRegistrationIntent;
    readonly registration: Registration;
  }) => Effect.Effect<
    { readonly fingerprint: string; readonly eligible: boolean },
    PersistenceMappingError
  >;
  /** Required for an explicitly bound native/DO command: no asynchronous callback
   * is evaluated inside the physical owner. Standalone inspection is pre-owner. */
  readonly inspectSync?: (input: {
    readonly intent: OAuthRegistrationIntent;
    readonly registration: Registration;
  }) => { readonly fingerprint: string; readonly eligible: boolean };
  /** Type projection, never the original wire transformation. */
  readonly snapshot: (
    registration: Registration,
  ) => Effect.Effect<Registration, PersistenceMappingError>;
  readonly snapshotSync?: (registration: Registration) => Registration;
  /** Canonical bounded storage of Registration.Type. These are Type codecs, not
   * the original wire decoder/encoder; decode(encode(value)) must encode identically.
   * The engine writes and roundtrip-checks this exact string (maximum 1 MiB). */
  readonly application: {
    readonly encode: (registration: Registration) => string;
    readonly decode: (stored: string) => Registration;
  };
  readonly eligibility: {
    /** Stable application authority anchors, in one configured global order.
     * Omit only for immutable/tuple-local policy or an equivalent explicit outer
     * owner lock. Each scope must match 1..64 rows, never an absent quota row.
     * Locks precede tuple/intent/command locks; postcondition owns changed state. */
    readonly guards?: ReadonlyArray<
      OAuthRegistrationGuardDescriptor<Registration, N, Expression, Descriptor>
    >;
    readonly admission: (input: {
      readonly intent: OAuthRegistrationIntent;
      readonly registration: Registration;
      readonly nativeSubjectId?: N;
    }) => Expression;
    /** Evaluated after subject/application writes, including appended coordinator
     * writes. May assert consumption of the admission invitation/quota. */
    readonly postcondition: (input: {
      readonly intent: OAuthRegistrationIntent;
      readonly registration: Registration;
      readonly nativeSubjectId?: N;
    }) => Expression;
  };
  readonly allocateProvisioningIdentity: Effect.Effect<string, PersistenceMappingError>;
  readonly retentionMillis: number;
}

export interface OAuthRegistrationGuardTable<
  T extends Table,
  Registration,
  N,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: T["table"];
  readonly orderBy: Column<T>;
  readonly condition: (input: {
    readonly intent: OAuthRegistrationIntent;
    readonly registration: Registration;
    readonly nativeSubjectId?: N;
  }) => Expression;
}

export interface OAuthRegistrationGuardDescriptor<
  Registration,
  N,
  Expression extends SqlExpression = SqlExpression,
  Descriptor extends object = object,
> {
  readonly table: Descriptor;
  readonly orderBy: string;
  readonly condition: OAuthRegistrationGuardTable<Table, Registration, N, Expression>["condition"];
}

export const oauthRegistrationGuardTable = <
  T extends Table,
  Registration,
  N,
  Expression extends SqlExpression = SqlExpression,
>(
  input: OAuthRegistrationGuardTable<T, Registration, N, Expression>,
): OAuthRegistrationGuardDescriptor<Registration, N, Expression, T["table"]> =>
  Object.freeze({
    table: input.table,
    orderBy: input.orderBy,
    condition: input.condition,
  });

export type OAuthRegistrationMapping<
  Registration,
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  T extends Table,
  I extends Table,
  R extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
  Descriptor extends object = object,
> = OAuthRegistrationBase<Registration, T, O, I, R, N, Expression, Descriptor> &
  (
    | {
        readonly mode: "pending";
        readonly allocatePendingReference: Effect.Effect<string, PersistenceMappingError>;
      }
    | {
        readonly mode: "atomic";
        readonly subjectId: SubjectIdCodec<N>;
        readonly subject: OAuthSubjectReadTable<S, Expression>;
        readonly credential: OAuthCredentialTable<C, N, Expression>;
        readonly authority: OAuthAuthorityTable<AC, N, Expression>;
        readonly allocateSubjectId: Effect.Effect<N, PersistenceMappingError>;
        readonly allocateCredentialId: Effect.Effect<string, PersistenceMappingError>;
        readonly allocateRevision: Effect.Effect<SecurityRevision, PersistenceMappingError>;
        readonly encodeSubjectInsert: (
          input: { readonly intent: OAuthRegistrationIntent; readonly registration: Registration },
          ids: { readonly subjectId: N; readonly securityRevision: SecurityRevision },
        ) => S["insert"];
      }
  );

/** Heterogeneous descriptors are made by typed factories and projected privately. */
export interface OAuthEligibilityDescriptor<
  N,
  Expression extends SqlExpression = SqlExpression,
  Descriptor extends object = object,
> {
  readonly _tag: "OAuthEligibilityDescriptor";
  readonly scope: string;
  readonly table: Descriptor;
  readonly subjectId: string;
  readonly credentialId: string;
  readonly revision: string;
  readonly condition: (subjectId: N) => Expression;
  readonly decode: (row: unknown) => OAuthEligibilityFact | undefined;
}

export const oauthEligibilityTable = <
  T extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
>(
  input: OAuthEligibilityTable<T, N, Expression>,
): OAuthEligibilityDescriptor<N, Expression, T["table"]> => {
  const { table, subjectId, credentialId, revision, scope, condition, decode } = input;

  return Object.freeze({
    _tag: "OAuthEligibilityDescriptor",
    table,
    subjectId,
    credentialId,
    revision,
    scope,
    condition,
    // The query owner supplies rows selected from this descriptor's mapped table.
    decode: (row: unknown) => decode(row as T["select"]),
  });
};

export interface OAuthCleanupDescriptor<
  N,
  Expression extends SqlExpression = SqlExpression,
  Descriptor extends object = object,
> {
  readonly table: Descriptor;
  readonly subjectId: string;
  readonly condition: OAuthCleanupTable<Table, N, Expression>["condition"];
}

export const oauthCleanupTable = <
  T extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
>(
  input: OAuthCleanupTable<T, N, Expression>,
): OAuthCleanupDescriptor<N, Expression, T["table"]> =>
  Object.freeze({ table: input.table, subjectId: input.subjectId, condition: input.condition });

/** A stable application/reference lock acquired before an ownership target.
 * Missing rows retain ownership. Conditions use detached native IDs; every
 * writer of the guarded reference follows the same order. */
export interface OAuthReferenceGuardTable<
  T extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
> {
  readonly table: T["table"];
  readonly orderBy: Column<T>;
  readonly condition: (input: {
    readonly identity: typeof OAuthExternalIdentity.Type;
    readonly identityKey: string;
    readonly subjectId: N;
  }) => Expression | Effect.Effect<Expression, PlatformError.PlatformError, Crypto.Crypto>;
}

export interface OAuthReferenceGuardDescriptor<
  N,
  Expression extends SqlExpression = SqlExpression,
  Descriptor extends object = object,
> {
  readonly table: Descriptor;
  readonly orderBy: string;
  readonly condition: OAuthReferenceGuardTable<Table, N, Expression>["condition"];
}

export const oauthReferenceGuardTable = <
  T extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
>(
  input: OAuthReferenceGuardTable<T, N, Expression>,
): OAuthReferenceGuardDescriptor<N, Expression, T["table"]> =>
  Object.freeze({
    table: input.table,
    orderBy: input.orderBy,
    condition: input.condition,
  });

export interface OAuthAccountsMapping<
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  F extends Table,
  T extends Table,
  U extends Table,
  N,
  Expression extends SqlExpression = SqlExpression,
  Descriptor extends object = object,
> {
  readonly subject: OAuthSubjectTable<S, Expression>;
  readonly ownership: OAuthOwnershipMutation<T, O, N, Expression>;
  readonly credential: OAuthCredentialTable<C, N, Expression>;
  readonly authority: OAuthAuthorityTable<AC, N, Expression>;
  readonly flow: OAuthFlowTable<F>;
  readonly command: OAuthUnlinkCommandTable<U>;
  readonly subjectId: SubjectIdCodec<N>;
  readonly clock: OAuthClock<Expression>;
  readonly constraints: typeof requiredOAuthSignInConstraints &
    typeof requiredOAuthAccountsConstraints;
  readonly tupleConstraints: typeof requiredOAuthTupleConstraints;
  readonly eligibility: ReadonlyArray<OAuthEligibilityDescriptor<N, Expression, Descriptor>>;
  readonly cleanup: ReadonlyArray<OAuthCleanupDescriptor<N, Expression, Descriptor>>;
  readonly metadata: OAuthMetadataPolicy<N, Expression>;
  readonly sessionInvalidation: "same-authority-immediate" | "original-absolute-expiry";
  /** Omit only when connected access is absent. A predicate alone conservatively
   * retains ownership; release also needs all configured guard rows below. */
  readonly connectedReference?: (input: {
    readonly identityKey: string;
    readonly subjectId: N;
  }) => Expression;
  /** At most 32 descriptors, each locking 1..64 stable rows in supplied order.
   * Missing/empty guards retain Owned, even when the reference predicate is false. */
  readonly connectedReferenceGuards?: ReadonlyArray<
    OAuthReferenceGuardDescriptor<N, Expression, Descriptor>
  >;
  readonly allocateCredentialId: Effect.Effect<string, PersistenceMappingError>;
  readonly allocateRevision: Effect.Effect<SecurityRevision, PersistenceMappingError>;
}

export interface OAuthRegistrationAuthority<Registration> {
  readonly read: (
    access: OAuthRegistrationAccess,
  ) => Effect.Effect<OAuthRegistrationInspection | undefined, OAuthUnavailable>;
  readonly inspect: (input: {
    readonly intent: OAuthRegistrationIntent;
    readonly registration: Registration;
  }) => Effect.Effect<
    {
      readonly fingerprint: TokenDigest;
      readonly eligible: boolean;
    },
    OAuthUnavailable
  >;
  readonly register: <A>(
    input: {
      readonly access: OAuthRegistrationAccess;
      readonly intent: OAuthRegistrationIntent;
      readonly commandId: typeof OAuthCommandId.Type;
      readonly registration: Registration;
      readonly fingerprint: TokenDigest;
    },
    prepare: PrepareOAuthCommit<OAuthRegistrationDecision, A>,
  ) => Effect.Effect<PreparedCommit<A>, OAuthUnavailable>;
  readonly cleanup: <A>(
    input: OAuthCleanupInput,
    prepare: PrepareOAuthCommit<{ readonly removed: number; readonly hasMore: boolean }, A>,
  ) => Effect.Effect<PreparedCommit<A>, OAuthUnavailable>;
}
