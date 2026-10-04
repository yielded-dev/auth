import { makeWithDefaults } from "drizzle-orm/effect-d1";
import { Layer } from "effect";

import { Database } from "./drizzle/d1-database";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/d1-totp";

export { Database } from "./drizzle/d1-database";

export {
  makeD1OAuthAccountsServices as makeOAuthAccountsServices,
  makeD1OAuthSignInServices as makeOAuthSignInServices,
  makeD1OAuthRegistrationIntentServices as makeOAuthRegistrationIntentServices,
  makeD1OAuthRegistrationServices as makeOAuthRegistrationServices,
  coordinateD1OAuthRegistration as coordinateOAuthRegistration,
  coordinateD1OAuthSignIn as coordinateOAuthSignIn,
  coordinateD1OAuthRegistrationIntents as coordinateOAuthRegistrationIntents,
  coordinateD1OAuthAccounts as coordinateOAuthAccounts,
} from "./drizzle/d1-oauth";

export {
  coordinateD1AuthenticationAuthority as coordinateAuthenticationAuthority,
  coordinateD1PendingAuthentication as coordinatePendingAuthentication,
  coordinateD1SignedSessionValidity as coordinateSignedSessionValidity,
  coordinateD1StatefulSessions as coordinateStatefulSessions,
  makeD1AuthenticationAuthorityServices as makeAuthenticationAuthorityServices,
  makeD1PendingAuthenticationServices as makePendingAuthenticationServices,
  makeD1SignedSessionValidityServices as makeSignedSessionValidityServices,
  makeD1StatefulSessionServices as makeStatefulSessionServices,
} from "./drizzle/d1-sessions";

export {
  coordinateD1ProofPersistence as coordinateProofPersistence,
  makeD1ProofPersistenceServices as makeProofPersistenceServices,
} from "./drizzle/d1-proofs";

export {
  coordinateD1PasswordPersistence as coordinatePasswordPersistence,
  coordinateD1PasswordRegistration as coordinatePasswordRegistration,
  makeD1PasswordPersistenceServices as makePasswordPersistenceServices,
  makeD1PasswordRegistrationServices as makePasswordRegistrationServices,
} from "./drizzle/d1-passwords";

export {
  coordinateD1EmailAddress as coordinateEmailAddress,
  coordinateD1EmailRegistration as coordinateEmailRegistration,
  makeD1EmailAddressServices as makeEmailAddressServices,
  makeD1EmailRegistrationServices as makeEmailRegistrationServices,
  makeD1EmailSignInServices as makeEmailSignInServices,
} from "./drizzle/d1-emails";

export const commitMode = "batch" as const;

export {
  makeD1SessionStepUpServices as makeSessionStepUpServices,
  coordinateD1SessionStepUp as coordinateSessionStepUp,
} from "./drizzle/d1-sessions";

export {
  makeD1PasswordPreparedPersistenceServices as makePasswordPreparedPersistenceServices,
  coordinateD1PasswordPreparedPersistence as coordinatePasswordPreparedPersistence,
} from "./drizzle/d1-password-prepared";

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

export {
  makePasskeyCredentialServices,
  makePasskeyPersistenceServices,
  makePasskeyEnrollmentContextServices,
  makePasskeyRegistrationCeremonyServices,
  coordinatePasskeyPersistence,
  coordinatePasskeyRegistrationCeremony,
  makePasskeyManagementServices,
  makePasskeyRegistrationServices,
  coordinatePasskeyManagement,
  coordinatePasskeyRegistration,
} from "./drizzle/d1-passkey";

export { D1BatchStatements } from "./drizzle/D1BatchStatements";

export { makePhonePersistenceServices, coordinatePhonePersistence } from "./drizzle/d1-phone";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/d1-oauth-connected";

export {
  makeD1SubjectProvisioningServices as makeSubjectProvisioningServices,
  makeD1ExternalIdentityServices as makeExternalIdentityServices,
  makeD1IdentityServices as makeIdentityServices,
} from "./drizzle/d1-identity";

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
