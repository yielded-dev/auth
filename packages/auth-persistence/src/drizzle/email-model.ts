import type { EmailAction, EmailRegistrationDecision } from "@yielded/auth/Email";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import type { ProofBinding, ProofContinuationId, ProofPurpose } from "@yielded/auth/Proofs";
import type { TokenDigest } from "@yielded/auth/Schema";
import type { AuthenticationRequirement, SecurityRevision } from "@yielded/auth/Sessions";
import type { InferInsertModel, InferSelectModel, SQL, Table } from "drizzle-orm";
import type { Effect } from "effect";

import type { PersistenceMappingError, SubjectIdCodec } from "./model";

type ColumnKey<T extends Table> = Extract<keyof T["_"]["columns"], string>;

export interface EmailSubjectReadTable<Subject extends Table> {
  readonly table: Subject;
  readonly id: ColumnKey<Subject>;
  readonly status: ColumnKey<Subject>;
  readonly securityRevision: ColumnKey<Subject>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly d1ActiveStatusValue?: unknown;
}

export interface EmailSubjectTable<Subject extends Table> extends EmailSubjectReadTable<Subject> {
  readonly decodeActionRequirement: (
    row: InferSelectModel<Subject>,
    action: EmailAction,
  ) => Effect.Effect<AuthenticationRequirement, PersistenceMappingError>;
  readonly nextSecurityRevision?: (
    current: SecurityRevision,
  ) => Effect.Effect<SecurityRevision, PersistenceMappingError>;
  readonly nextSecurityRevisionSync?: (current: SecurityRevision) => SecurityRevision;
  readonly d1ActiveStatusValue?: unknown;
}

export interface EmailIdentifierReadTable<Identifier extends Table> {
  readonly table: Identifier;
  readonly namespace: ColumnKey<Identifier>;
  readonly value: ColumnKey<Identifier>;
  readonly subjectId: ColumnKey<Identifier>;
  readonly verifiedAt: ColumnKey<Identifier>;
  readonly bindingRevision: ColumnKey<Identifier>;
  readonly isCurrent: (row: InferSelectModel<Identifier>) => boolean;
}

export interface EmailIdentifierTable<
  Identifier extends Table,
  NativeSubjectId,
> extends EmailIdentifierReadTable<Identifier> {
  /** True only for an active, unverified binding. Confirming it preserves existing sessions. */
  readonly isMutableTarget: (row: InferSelectModel<Identifier>) => boolean;
  readonly encodeVerifiedInsert: (input: {
    readonly identifier: LoginIdentifier;
    readonly subjectId: NativeSubjectId;
    readonly verifiedAtMillis: number;
    readonly bindingRevision: SecurityRevision;
  }) => InferInsertModel<Identifier>;
  readonly encodeVerification: (input: {
    readonly verifiedAtMillis: number;
    readonly bindingRevision: SecurityRevision;
  }) => Partial<InferInsertModel<Identifier>>;
  /** Must make the selected source unavailable to sign-in. */
  readonly encodeRetirement: (input: {
    readonly source: LoginIdentifier;
    readonly bindingRevision: SecurityRevision;
  }) => Partial<InferInsertModel<Identifier>>;
  readonly d1CurrentCondition?: (input: {
    readonly identifier: LoginIdentifier;
    readonly nativeSubjectId: NativeSubjectId;
    readonly bindingRevision: SecurityRevision;
  }) => SQL;
  readonly d1MutableTargetCondition?: (input: {
    readonly identifier: LoginIdentifier;
    readonly nativeSubjectId: NativeSubjectId;
  }) => SQL;
}

export interface EmailCredentialReadTable<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  _NativeSubjectId,
> {
  readonly table: Credential;
  readonly moduleId: ColumnKey<Credential>;
  readonly subjectId: ColumnKey<Credential>;
  readonly credentialId: ColumnKey<Credential>;
  readonly identifierNamespace: ColumnKey<Credential>;
  readonly identifierValue: ColumnKey<Credential>;
  readonly credentialRevision: ColumnKey<Credential>;
  readonly status: ColumnKey<Credential>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly decode: (input: {
    readonly moduleId: string;
    readonly subject: InferSelectModel<Subject>;
    readonly identifier: InferSelectModel<Identifier>;
    readonly credential: InferSelectModel<Credential>;
  }) => Effect.Effect<
    import("@yielded/auth/Email").EmailCredentialSnapshot,
    PersistenceMappingError
  >;
}

export interface EmailCredentialTable<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> extends EmailCredentialReadTable<Subject, Identifier, Credential, NativeSubjectId> {
  readonly encodeVerifiedInsert: (input: {
    readonly moduleId: string;
    readonly subjectId: NativeSubjectId;
    readonly credentialId: string;
    readonly identifier: LoginIdentifier;
    readonly credentialRevision: SecurityRevision;
  }) => InferInsertModel<Credential>;
  readonly encodeActivation: (input: {
    readonly identifier: LoginIdentifier;
    readonly credentialRevision: SecurityRevision;
  }) => Partial<InferInsertModel<Credential>>;
  readonly encodeRetirement: (input: {
    readonly source: LoginIdentifier;
    readonly credentialRevision: SecurityRevision;
  }) => Partial<InferInsertModel<Credential>>;
  readonly d1ActiveStatusValue?: unknown;
}

export interface EmailAuthorityCredentialTable<Credential extends Table, NativeSubjectId> {
  readonly table: Credential;
  readonly subjectId: ColumnKey<Credential>;
  readonly credentialId: ColumnKey<Credential>;
  readonly revision: ColumnKey<Credential>;
  readonly status: ColumnKey<Credential>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly encodeInsert: (input: {
    readonly subjectId: NativeSubjectId;
    readonly credentialId: string;
    readonly revision: SecurityRevision;
  }) => InferInsertModel<Credential>;
  readonly encodeActivation: (revision: SecurityRevision) => Partial<InferInsertModel<Credential>>;
  readonly encodeRetirement: (revision: SecurityRevision) => Partial<InferInsertModel<Credential>>;
  readonly d1ActiveStatusValue?: unknown;
}

export interface EmailCommandTable<Command extends Table> {
  readonly table: Command;
  readonly moduleId: ColumnKey<Command>;
  readonly commandId: ColumnKey<Command>;
  readonly action: ColumnKey<Command>;
  readonly bindingDigest: ColumnKey<Command>;
  readonly retentionUntil: ColumnKey<Command>;
  readonly encodeInsert: (input: {
    readonly moduleId: string;
    readonly commandId: string;
    readonly action: EmailAction;
    readonly bindingDigest: TokenDigest;
    readonly retentionUntilMillis: number;
  }) => InferInsertModel<Command>;
}

export interface RequiredEmailSignInConstraints {
  readonly identifier: "unique(identifier.namespace,identifier.value)";
  readonly credentialId: "unique(emailCredential.moduleId,emailCredential.credentialId)";
  readonly credentialIdentifier: "unique(emailCredential.moduleId,emailCredential.identifierNamespace,emailCredential.identifierValue)";
}

export const requiredEmailSignInConstraints: RequiredEmailSignInConstraints = {
  identifier: "unique(identifier.namespace,identifier.value)",
  credentialId: "unique(emailCredential.moduleId,emailCredential.credentialId)",
  credentialIdentifier:
    "unique(emailCredential.moduleId,emailCredential.identifierNamespace,emailCredential.identifierValue)",
};

export interface EmailSignInMapping<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> {
  readonly subject: EmailSubjectReadTable<Subject>;
  readonly identifier: EmailIdentifierReadTable<Identifier>;
  readonly credential: EmailCredentialReadTable<Subject, Identifier, Credential, NativeSubjectId>;
  readonly subjectId: SubjectIdCodec<NativeSubjectId>;
  readonly constraints: RequiredEmailSignInConstraints;
  readonly decodeInstant: (native: unknown) => Effect.Effect<number, PersistenceMappingError>;
}

export interface RequiredEmailAddressConstraints extends RequiredEmailSignInConstraints {
  readonly authorityCredential: "unique(authorityCredential.subjectId,authorityCredential.credentialId)";
  readonly command: "unique(emailCommand.moduleId,emailCommand.commandId)";
}

export const requiredEmailAddressConstraints: RequiredEmailAddressConstraints = {
  ...requiredEmailSignInConstraints,
  authorityCredential: "unique(authorityCredential.subjectId,authorityCredential.credentialId)",
  command: "unique(emailCommand.moduleId,emailCommand.commandId)",
};

export interface EmailD1Clock {
  readonly engineNow: SQL;
  readonly engineNowMillis: SQL;
  readonly engineInstantPlus: (millis: number) => SQL;
}

export interface EmailAddressMapping<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  AuthorityCredential extends Table,
  Command extends Table,
  NativeSubjectId,
> extends EmailSignInMapping<Subject, Identifier, Credential, NativeSubjectId> {
  readonly subject: EmailSubjectTable<Subject>;
  readonly identifier: EmailIdentifierTable<Identifier, NativeSubjectId>;
  readonly credential: EmailCredentialTable<Subject, Identifier, Credential, NativeSubjectId>;
  readonly authorityCredential: EmailAuthorityCredentialTable<AuthorityCredential, NativeSubjectId>;
  readonly command: EmailCommandTable<Command>;
  readonly constraints: RequiredEmailAddressConstraints;
  readonly addressCardinality: "single" | "multiple";
  readonly changeDisposition: "retire-source";
  readonly allocateCredentialId?: Effect.Effect<string, PersistenceMappingError>;
  readonly allocateCredentialIdSync?: () => string;
  readonly allocateRevision?: Effect.Effect<SecurityRevision, PersistenceMappingError>;
  readonly allocateRevisionSync?: () => SecurityRevision;
  readonly encodeInstant: (epochMillis: number) => unknown;
  readonly commandRetentionMillis: number;
  readonly sessionInvalidation: "same-authority-immediate" | "original-absolute-expiry";
  readonly isCommandConflict: (cause: unknown) => boolean;
  readonly isIdentifierConflict: (cause: unknown) => boolean;
  readonly isCredentialConflict: (cause: unknown) => boolean;
  readonly d1?: EmailD1Clock;
}

export type D1EmailAddressMapping<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  AuthorityCredential extends Table,
  Command extends Table,
  NativeSubjectId,
> = EmailAddressMapping<
  Subject,
  Identifier,
  Credential,
  AuthorityCredential,
  Command,
  NativeSubjectId
> & {
  readonly d1: EmailD1Clock;
  readonly subject: EmailSubjectTable<Subject> & { readonly d1ActiveStatusValue: unknown };
  readonly identifier: EmailIdentifierTable<Identifier, NativeSubjectId> & {
    readonly d1CurrentCondition: NonNullable<
      EmailIdentifierTable<Identifier, NativeSubjectId>["d1CurrentCondition"]
    >;
    readonly d1MutableTargetCondition: NonNullable<
      EmailIdentifierTable<Identifier, NativeSubjectId>["d1MutableTargetCondition"]
    >;
  };
  readonly credential: EmailCredentialTable<Subject, Identifier, Credential, NativeSubjectId> & {
    readonly d1ActiveStatusValue: unknown;
  };
  readonly authorityCredential: EmailAuthorityCredentialTable<
    AuthorityCredential,
    NativeSubjectId
  > & { readonly d1ActiveStatusValue: unknown };
};

export type EmailRegistrationState = "pending" | "registered";

export interface EmailRegistrationIntent<Registration> {
  readonly moduleId: string;
  readonly commandId: string;
  readonly identifier: LoginIdentifier;
  readonly registration: Registration;
  readonly fingerprint: TokenDigest;
  readonly completion: {
    readonly moduleId: string;
    readonly purpose: ProofPurpose;
    readonly continuationId: ProofContinuationId;
    readonly binding: ProofBinding;
  };
}

export interface EmailRegistrationTable<Registration, Request extends Table, NativeSubjectId> {
  readonly table: Request;
  readonly moduleId: ColumnKey<Request>;
  readonly commandId: ColumnKey<Request>;
  readonly fingerprint: ColumnKey<Request>;
  readonly state: ColumnKey<Request>;
  readonly subjectId: ColumnKey<Request>;
  readonly pendingReference: ColumnKey<Request>;
  readonly retentionUntil: ColumnKey<Request>;
  readonly encodeInsert: (
    input: EmailRegistrationIntent<Registration>,
    state: {
      readonly state: EmailRegistrationState;
      readonly nativeSubjectId?: NativeSubjectId;
      readonly pendingReference?: string;
      readonly retentionUntilMillis: number;
    },
  ) => InferInsertModel<Request>;
  readonly decodeReplay: (
    row: InferSelectModel<Request>,
  ) => Effect.Effect<
    Exclude<EmailRegistrationDecision, { readonly _tag: "Registered" }>,
    PersistenceMappingError
  >;
}

export interface EmailRegistrationProvisioning<
  Registration,
  Subject extends Table,
  NativeSubjectId,
> {
  readonly encodeSubjectInsert: (
    input: EmailRegistrationIntent<Registration>,
    values: {
      readonly nativeSubjectId: NativeSubjectId | undefined;
      readonly securityRevision: SecurityRevision;
    },
  ) => InferInsertModel<Subject>;
  readonly allocateSubjectId?: Effect.Effect<NativeSubjectId, PersistenceMappingError>;
  readonly allocateSubjectIdSync?: () => NativeSubjectId;
  readonly decodeGeneratedId?: (
    rows: ReadonlyArray<unknown>,
  ) => Effect.Effect<NativeSubjectId, PersistenceMappingError>;
}

export interface EmailRegistrationIdentifierTable<Identifier extends Table, NativeSubjectId> {
  readonly table: Identifier;
  readonly namespace: ColumnKey<Identifier>;
  readonly value: ColumnKey<Identifier>;
  readonly subjectId: ColumnKey<Identifier>;
  readonly verifiedAt: ColumnKey<Identifier>;
  readonly bindingRevision: ColumnKey<Identifier>;
  readonly isCurrent: (row: InferSelectModel<Identifier>) => boolean;
  readonly d1CurrentCondition?: (input: {
    readonly identifier: LoginIdentifier;
    readonly nativeSubjectId: NativeSubjectId;
    readonly bindingRevision: SecurityRevision;
  }) => SQL;
  readonly encodeVerifiedInsert: (input: {
    readonly identifier: LoginIdentifier;
    readonly subjectId: NativeSubjectId;
    readonly verifiedAtMillis: number;
    readonly bindingRevision: SecurityRevision;
  }) => InferInsertModel<Identifier>;
}

export interface EmailRegistrationCredentialTable<Credential extends Table, NativeSubjectId> {
  readonly table: Credential;
  readonly moduleId: ColumnKey<Credential>;
  readonly subjectId: ColumnKey<Credential>;
  readonly credentialId: ColumnKey<Credential>;
  readonly identifierNamespace: ColumnKey<Credential>;
  readonly identifierValue: ColumnKey<Credential>;
  readonly credentialRevision: ColumnKey<Credential>;
  readonly status: ColumnKey<Credential>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly d1ActiveStatusValue?: unknown;
  readonly encodeVerifiedInsert: (input: {
    readonly moduleId: string;
    readonly subjectId: NativeSubjectId;
    readonly credentialId: string;
    readonly identifier: LoginIdentifier;
    readonly credentialRevision: SecurityRevision;
  }) => InferInsertModel<Credential>;
}

export interface EmailRegistrationAuthorityCredentialTable<
  Credential extends Table,
  NativeSubjectId,
> {
  readonly table: Credential;
  readonly subjectId: ColumnKey<Credential>;
  readonly credentialId: ColumnKey<Credential>;
  readonly revision: ColumnKey<Credential>;
  readonly status: ColumnKey<Credential>;
  readonly isActiveStatus: (value: unknown) => boolean;
  readonly d1ActiveStatusValue?: unknown;
  readonly encodeInsert: (input: {
    readonly subjectId: NativeSubjectId;
    readonly credentialId: string;
    readonly revision: SecurityRevision;
  }) => InferInsertModel<Credential>;
}

export interface RequiredEmailRegistrationConstraints extends RequiredEmailSignInConstraints {
  readonly authorityCredential: "unique(authorityCredential.subjectId,authorityCredential.credentialId)";
  readonly request: "unique(emailRegistration.moduleId,emailRegistration.commandId)";
  readonly pendingReference: "unique(emailRegistration.pendingReference)";
}

export const requiredEmailRegistrationConstraints: RequiredEmailRegistrationConstraints = {
  ...requiredEmailSignInConstraints,
  authorityCredential: "unique(authorityCredential.subjectId,authorityCredential.credentialId)",
  request: "unique(emailRegistration.moduleId,emailRegistration.commandId)",
  pendingReference: "unique(emailRegistration.pendingReference)",
};

type EmailRegistrationBase<Registration, Request extends Table, NativeSubjectId> = {
  readonly registration: EmailRegistrationTable<Registration, Request, NativeSubjectId>;
  readonly constraints: Pick<RequiredEmailRegistrationConstraints, "request" | "pendingReference">;
  readonly inspect: (input: {
    readonly identifier: LoginIdentifier;
    readonly registration: Registration;
  }) => Effect.Effect<
    { readonly fingerprint: TokenDigest; readonly eligible: boolean },
    PersistenceMappingError
  >;
  /** Projects one detached value of the factory-specific Registration Type. */
  readonly snapshotRegistration: (
    registration: Registration,
  ) => Effect.Effect<Registration, PersistenceMappingError>;
  /** Required by synchronous transaction-bound services. */
  readonly snapshotRegistrationSync?: (registration: Registration) => Registration;
  /** Required by synchronous Durable Object transaction-bound services. */
  readonly inspectSync?: (input: {
    readonly identifier: LoginIdentifier;
    readonly registration: Registration;
  }) => { readonly fingerprint: TokenDigest; readonly eligible: boolean };
  readonly allocatePendingReference?: Effect.Effect<string, PersistenceMappingError>;
  readonly allocatePendingReferenceSync?: () => string;
  readonly encodeInstant: (epochMillis: number) => unknown;
  readonly retentionMillis: number;
  readonly isRequestConflict: (cause: unknown) => boolean;
};

export type EmailRegistrationMapping<
  Registration,
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  AuthorityCredential extends Table,
  Request extends Table,
  NativeSubjectId,
> = EmailRegistrationBase<Registration, Request, NativeSubjectId> &
  (
    | {
        readonly mode: "atomic";
        readonly subject: EmailSubjectReadTable<Subject>;
        readonly identifier: EmailRegistrationIdentifierTable<Identifier, NativeSubjectId>;
        readonly credential: EmailRegistrationCredentialTable<Credential, NativeSubjectId>;
        readonly authorityCredential: EmailRegistrationAuthorityCredentialTable<
          AuthorityCredential,
          NativeSubjectId
        >;
        readonly subjectId: SubjectIdCodec<NativeSubjectId>;
        readonly constraints: RequiredEmailRegistrationConstraints;
        readonly allocateCredentialId?: Effect.Effect<string, PersistenceMappingError>;
        readonly allocateCredentialIdSync?: () => string;
        readonly allocateRevision?: Effect.Effect<SecurityRevision, PersistenceMappingError>;
        readonly allocateRevisionSync?: () => SecurityRevision;
        readonly isIdentifierConflict: (cause: unknown) => boolean;
        readonly isCredentialConflict: (cause: unknown) => boolean;
        readonly provisioning: EmailRegistrationProvisioning<
          Registration,
          Subject,
          NativeSubjectId
        > &
          (
            | {
                readonly idMode: "allocated";
                readonly allocateSubjectId: Effect.Effect<NativeSubjectId, PersistenceMappingError>;
              }
            | {
                readonly idMode: "synchronous";
                readonly allocateSubjectIdSync: () => NativeSubjectId;
              }
            | {
                readonly idMode: "generated";
                readonly decodeGeneratedId: (
                  rows: ReadonlyArray<unknown>,
                ) => Effect.Effect<NativeSubjectId, PersistenceMappingError>;
              }
          );
      }
    | { readonly mode: "pending" }
  );

export type AnyEmailSignInMapping = EmailSignInMapping<Table, Table, Table, unknown>;

export type AnyEmailAddressMapping = EmailAddressMapping<
  Table,
  Table,
  Table,
  Table,
  Table,
  unknown
>;

export type AnyEmailRegistrationMapping<Registration = unknown> = EmailRegistrationMapping<
  Registration,
  Table,
  Table,
  Table,
  Table,
  Table,
  unknown
>;

export type D1EmailRegistrationMapping<
  Registration,
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  AuthorityCredential extends Table,
  Request extends Table,
  NativeSubjectId,
> = EmailRegistrationMapping<
  Registration,
  Subject,
  Identifier,
  Credential,
  AuthorityCredential,
  Request,
  NativeSubjectId
> & { readonly d1: EmailD1Clock };
