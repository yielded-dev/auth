/** Shared mapping metadata, authentication decisions and workflow capabilities.
 * Each backend owns its SQL statements, codecs and native transaction scope. */
export {
  type EmailSubjectReadTable,
  type EmailSubjectTable,
  type EmailIdentifierReadTable,
  type EmailIdentifierTable,
  type EmailCredentialReadTable,
  type EmailCredentialTable,
  type EmailAuthorityCredentialTable,
  type EmailCommandTable,
  type RequiredEmailSignInConstraints,
  requiredEmailSignInConstraints,
  type EmailSignInMapping,
  type RequiredEmailAddressConstraints,
  requiredEmailAddressConstraints,
  type EmailD1Clock,
  type EmailAddressMapping,
  type D1EmailAddressMapping,
  type EmailRegistrationState,
  type EmailRegistrationIntent,
  type EmailRegistrationTable,
  type EmailRegistrationProvisioning,
  type EmailRegistrationIdentifierTable,
  type EmailRegistrationCredentialTable,
  type EmailRegistrationAuthorityCredentialTable,
  type RequiredEmailRegistrationConstraints,
  requiredEmailRegistrationConstraints,
  type EmailRegistrationMapping,
  type AnyEmailSignInMapping,
  type AnyEmailAddressMapping,
  type AnyEmailRegistrationMapping,
  type D1EmailRegistrationMapping,
} from "./internal/models/email-model";

export {
  type PasskeyColumn,
  type PasskeyMappingSource,
  type PasskeyCredentialServices,
  type PasskeyPersistenceServices,
  passkeyCredentialsLayer,
  passkeyPersistenceLayer,
  type PasskeySubjectIdCodec,
  type PasskeyClock,
  type PasskeySubjectReadTable,
  type PasskeyFactorReadTable,
  type PasskeyCredentialReadTable,
  requiredPasskeyCredentialConstraints,
  type PasskeyCredentialMapping,
  type PasskeyFlowInsert,
  type PasskeyFlowTable,
  requiredPasskeyPersistenceConstraints,
  type PasskeyCeremonyMapping,
  type PasskeyPersistenceMapping,
  type D1PasskeyMapping,
} from "./internal/models/passkey-model";

export {
  type PasskeyRegistrationCeremonyCapabilities,
  type PasskeyRegistrationCeremonyServices,
  type PasskeyRegistrationCeremonyMapping,
} from "./internal/models/passkey-registration-ceremony-model";

export {
  type PasskeyCredentialInsert,
  type PasskeyWriteTables,
  type PasskeyInvalidationInput,
  type PasskeyInvalidationMutation,
  passkeyInvalidationMutation,
  type PasskeyManagementMapping,
  type PasskeyManagementServices,
  type PasskeyRegistrationWriter,
  type PasskeyRegistrationServices,
  type PasskeyRegistrationMapping,
} from "./internal/models/passkey-write-model";

export {
  type PasswordSubjectTable,
  type PasswordIdentifierTable,
  type PasswordAuthorityCredentialTable,
  type PasswordCredentialTable,
  type PasswordCommandTable,
  type RequiredPasswordConstraints,
  requiredPasswordConstraints,
  type PasswordConstraintClassifier,
  type PasswordD1Clock,
  type PasswordPersistenceMapping,
  type D1PasswordPersistenceMapping,
  type PasswordRegistrationState,
  type PasswordRegistrationIntent,
  type PasswordRegistrationTable,
  type PasswordRegistrationProvisioning,
  type RequiredPasswordRegistrationConstraints,
  requiredPasswordRegistrationConstraints,
  type PasswordRegistrationConstraintClassifier,
  type PasswordRegistrationMapping,
  type AnyPasswordPersistenceMapping,
  type AnyPasswordRegistrationMapping,
} from "./internal/models/password-model";

export {
  type ProofAction,
  type ProofScopeKind,
  type ProofGenerationState,
  type ProofDeliveryState,
  type ProofCommandKind,
  type ProofCommandDecision,
  type ProofScopeKeys,
  type ProofAuthorityInput,
  type ProofAuthorityTables,
  type ProofRequestTable,
  type ProofSeriesTable,
  type ProofGenerationTable,
  type ProofContinuationRecord,
  type ProofContinuationTable,
  type ProofRateScopeTable,
  type ProofAbuseEventTable,
  type ProofFailureEventTable,
  type ProofCommandTable,
  type RequiredProofConstraints,
  requiredProofConstraints,
  type ProofConstraintClassifier,
  type ProofD1Clock,
  type ProofPersistenceMapping,
  type D1ProofPersistenceMapping,
  type AnyProofPersistenceMapping,
} from "./internal/models/proof-model";

export {
  type SessionIdCodec,
  type SessionSubjectTables,
  type SessionAuthorityTables,
  type SessionFlowTables,
  type StatefulSessionTables,
  type PendingAuthenticationTables,
  type SignedSessionValidityTables,
  type RequiredSessionConstraints,
  type RequiredPendingAuthenticationConstraints,
  type RequiredStatefulPendingConstraints,
  type RequiredSignedValidityConstraints,
  requiredSessionConstraints,
  requiredPendingAuthenticationConstraints,
  requiredStatefulPendingConstraints,
  requiredSignedValidityConstraints,
  type SessionConstraintClassifier,
  type AuthenticationAuthorityMapping,
  type StatefulSessionMapping,
  type PendingAuthenticationMapping,
  type SignedSessionValidityMapping,
  type D1SessionClockMapping,
  type D1AuthenticationAuthorityMapping,
  type D1PendingAuthenticationMapping,
  type D1StatefulSessionMapping,
  type D1SignedSessionValidityMapping,
} from "./internal/models/session-model";

export {
  type SessionStepUpIntentTables,
  type RequiredSessionStepUpConstraints,
  requiredSessionStepUpConstraints,
  type SessionStepUpSourceTables,
  type SessionStepUpMapping,
  type D1SessionStepUpMapping,
} from "./internal/models/step-up-model";

export { requireStandalone } from "./internal/standalone";

export {
  makeOAuthProxyPersistence,
  oauthProxyColumns,
  type OAuthProxySqlTable,
} from "./internal/oauth-proxy";

export {
  decodeStepUpIntent,
  encodeStepUpIntent,
  stepUpIntentLive,
  validateStepUpPlan,
  sameStepUpRevision,
  stepUpRotationMatches,
} from "./internal/step-up-state";

export { PersistenceMappingError, isMappedConstraintConflict } from "./internal/mapping-error";
export type { QueryFailure } from "./internal/query-failure";
export type { TableModel, SqlExpression } from "./internal/table-model";

export type {
  SessionSqlOptions,
  SessionTransactionOwner,
  SessionWorkflowPolicy,
  SessionSubjectAuthority,
  SessionFlowRead,
  SessionAuthorityRead,
  SessionAuthorityReader,
  SessionPendingRead,
  SessionPendingStore,
  SessionAuthorityStore,
  StatefulSessionStore,
  SessionVerificationRead,
  SessionVerificationReader,
} from "./internal/session-store";

export { PersistenceConfigurationError } from "./internal/configuration";
export { createPersistence } from "./internal/persistence";
export { makeMappings as makeStorageMappings } from "./internal/storage-mapping";
export { storageTables, type StorageRole, type StorageTable } from "./internal/storage-tables";
export type { SubjectIdCodec } from "./internal/models/common";
export type { PasswordRegistrationAuthority } from "./internal/registration-contract";

export type {
  BoundPersistence,
  ClaimsCodec,
  Definition,
  PersistenceApi,
} from "./internal/configuration";

export {
  validateStorage,
  validateStorageBatch,
  withStorageValidation,
  type PhysicalStorageTable,
  type StorageValidation,
} from "./internal/storage-validation";

export {
  makeAuthenticationAuthorityWorkflow,
  makeStatefulSessionWorkflow,
  captureSessionAuthority,
  sessionEvidenceRequirement,
  readSessionPending,
  ownSessionCommit,
} from "./internal/session-workflow";

export { preservesRevision, allocateSessionValue } from "./internal/session-policy";

export { CurrentProofStore } from "./internal/proof-store";

export type {
  ProofStoreError,
  ProofAuthorityRead,
  ProofAuthorityRequest,
  ProofScopeEntry,
  ProofScopeRequest,
  ProofSeriesKey,
  ProofSeriesRead,
  ProofGenerationRead,
  ProofRequestRead,
  ProofCompletionRead,
  ProofCompletionStore,
  ProofCleanupRead,
  ProofAttemptInput,
  ProofDeliverySettlementInput,
  ProofAttemptWrite,
  ProofDeliveryWrite,
  ProofStore,
} from "./internal/proof-store";

export {
  allocateProofVersion,
  sameProofBinding,
  proofScopeEntries,
  matchesProofAuthority,
  type ProofWorkflowPolicy,
  type ProofWorkflowOptions,
} from "./internal/proof-policy";

export {
  makeProofWorkflow,
  inspectProofCompletion,
  checkProofCompletion,
  completeProofIn,
  completeProofPlan,
  translateProofFailure,
} from "./internal/proof-workflow";

export type { PersistenceStoreError, PersistenceOwner } from "./internal/persistence-owner";

export type {
  PasswordStoreError,
  PasswordCredentialLookup,
  PasswordCredentialRead,
  PasswordMutationRevisions,
  PasswordMutationRead,
  PasswordStore,
} from "./internal/password-store";

export {
  samePasswordIdentifier,
  samePasswordCredential,
  passwordEvidenceSatisfiedAt,
  snapshotPasswordMutation,
  passwordProofCompletionMatches,
  allocatePasswordValue,
  allocatePasswordNextSecurityRevision,
  validatePasswordMutation,
  type PasswordWorkflowPolicy,
  type PasswordWorkflowOptions,
} from "./internal/password-policy";

export { makePasswordWorkflow, translatePasswordFailure } from "./internal/password-workflow";

export type {
  EmailStoreError,
  EmailAddressRequest,
  EmailMutationRevisions,
  EmailMutationRead,
  EmailAddressStore,
} from "./internal/email-store";

export {
  sameEmailRevision,
  emailActionModule,
  emailActionPurpose,
  emailCompletionMatches,
  snapshotEmailMutation,
  validateEmailMutation,
  type EmailWorkflowPolicy,
  type EmailWorkflowOptions,
} from "./internal/email-policy";

export { allocateEmailValue, allocateEmailSecurityRevision } from "./internal/email-policy";
export { makeEmailAddressWorkflow, translateEmailFailure } from "./internal/email-workflow";
export type { PasswordRegistrationStore } from "./internal/registration-store";

export {
  PhoneAdmissionReceipt,
  PhoneAdmissionCounter,
  PhoneCommandRecord,
  PhoneStoredState,
  phoneStateScope,
  validPhoneAdmissionInput,
  phoneAdmissionReplay,
  phoneAdmissionDecision,
  phoneAdmissionExpiry,
  phoneSignInSnapshot,
  type PhoneAdmissionInput,
} from "./internal/phone-policy";

export {
  composedPhoneAdmission,
  type PhoneStore,
  type PhoneStoreError,
} from "./internal/phone-store";

export type { MappingInput } from "./internal/configuration";

export {
  passkeyKey,
  passkeyCredentialKey,
  passkeyTargetRevision,
  passkeyStorage,
  passkeyCeremonyStorage,
  passkeyCredentialStorage,
  passkeyProfileStorage,
  passkeyRevisionStorage,
  samePasskeyCredential,
  samePasskeyRevision,
  passkeyAssertionPurposes,
  passkeyKnownSubject,
  passkeyMatchesAccess,
  assessPasskeyAction,
  validPasskeyActionEvidence,
  type PasskeyActionFacts,
} from "./internal/passkey-policy";

export type { PasskeyFeature } from "./internal/configuration";
export type { ComposedPasskeyInput, Backend } from "./internal/persistence";

export {
  passkeyCanonicalJson,
  passkeyDigest,
  passkeyEnrollmentDigest,
  passkeyRemoveDigest,
} from "./internal/passkey-actions";

export {
  passkeyOperationInputs,
  passkeyManagementInputs,
  passkeyManagementResults,
} from "./internal/passkey-inputs";

export {
  makeNativeSqlTables,
  nativeSqlAlias,
  sqlMapping,
  type NativeSqlTables,
  type SqlTable,
} from "./internal/native-sql-table";

export { randomId, digest } from "./internal/crypto";

export { makePasswordCredentials } from "./internal/password-credentials";

export { makeManagedPasskeys } from "./internal/passkey-managed";

export {
  makeNativePasskeyServices,
  makeBatchPasskeyServices,
  makeNativePasskeyCredentialServices,
} from "./internal/passkey-native";

export {
  makeNativePasskeyCeremonyServices,
  type NativePasskeyCeremonyMapping,
} from "./internal/passkey-native-ceremony";

export {
  makePasskeyNativeManagement,
  type NativePasskeyManagementMapping,
} from "./internal/passkey-native-write";

export {
  makePasskeyNativeRegistration,
  type NativePasskeyRegistrationMapping,
} from "./internal/passkey-native-registration";

export { type PasskeyNativeRead, type PasskeyNativeMapping } from "./internal/passkey-native-state";

export {
  makeSqlCommitExecutor,
  SqlBatchCommit,
  SqlNativeCommit,
  appendSqlBatchStatement,
  captureSqlBatchStatements,
} from "./internal/sql-commit";

export { samePasswordCredentialSnapshot } from "./internal/password-credentials";

export { storageKeyPlans } from "./internal/storage-plans";

export {
  type OAuthAction,
  type OAuthClock,
  type OAuthSubjectReadTable,
  type OAuthSubjectTable,
  type OAuthOwnershipReadTable,
  type OAuthOwnershipTable,
  type OAuthCredentialReadTable,
  type OAuthCredentialTable,
  type OAuthAuthorityReadTable,
  type OAuthAuthorityTable,
  type OAuthFlowTable,
  type OAuthEligibilityFact,
  type OAuthEligibilityTable,
  type OAuthCleanupTable,
  type OAuthRegistrationGuardTable,
  type OAuthRegistrationGuardDescriptor,
  oauthRegistrationGuardTable,
  type OAuthEligibilityDescriptor,
  oauthEligibilityTable,
  type OAuthCleanupDescriptor,
  oauthCleanupTable,
  type OAuthRegistrationIntentTable,
  type OAuthD1Mapping,
  requiredOAuthSignInConstraints,
  requiredOAuthRegistrationConstraints,
  type OAuthSignInMapping,
  type OAuthRegistrationIntentMapping,
  type OAuthRegistrationMapping,
  type OAuthAccountsMapping,
  type OAuthRegistrationAuthority,
} from "./internal/models/oauth-model";

export {
  type OAuthConnectedAction,
  type OAuthConnectedSubjectTable,
  type OAuthConnectedGrantTable,
  type OAuthConnectedRevocationJobTable,
  type OAuthConnectedPolicyInput,
  type OAuthConnectedSqlPolicy,
  requiredOAuthConnectedConstraints,
  requiredOAuthConnectedRevocationConstraints,
  type OAuthConnectedMapping,
  type OAuthConnectedRevocationMapping,
} from "./internal/models/oauth-connected-model";

export { makeNativeOAuthSignInServices } from "./internal/oauth/native-sign-in";
export type { OAuthNativeReadMapping } from "./internal/oauth/native-state";

export {
  makeNativeOAuthAccountsServices,
  type OAuthNativeAccountsMapping,
} from "./internal/oauth/native-accounts";

export {
  makeNativeOAuthRegistrationIntentServices,
  makeNativeOAuthRegistrationServices,
  type OAuthNativeRegistrationIntentMapping,
  type OAuthNativeRegistrationMapping,
} from "./internal/oauth/native-registration";

export { makeNativeOAuthConnectedServices } from "./internal/oauth/native-connected";
export type { OAuthNativeConnectedMapping } from "./internal/oauth/native-connected-state";

export {
  makeNativeOAuthRevocationServices,
  type OAuthNativeRevocationMapping,
} from "./internal/oauth/native-revocations";

export { captureOAuthMapping } from "./internal/oauth/state";
export * from "./internal/oauth/native-layers";
