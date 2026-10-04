import { makeWithDefaults } from "drizzle-orm/effect-mysql2";
import { Layer } from "effect";

import { Database } from "./drizzle/mysql-database";

export { Database } from "./drizzle/mysql-database";

export {
  coordinateMysqlAuthenticationAuthority as coordinateAuthenticationAuthority,
  coordinateMysqlPendingAuthentication as coordinatePendingAuthentication,
  coordinateMysqlSignedSessionValidity as coordinateSignedSessionValidity,
  coordinateMysqlStatefulSessions as coordinateStatefulSessions,
  makeMysqlAuthenticationAuthorityServices as makeAuthenticationAuthorityServices,
  makeMysqlPendingAuthenticationServices as makePendingAuthenticationServices,
  makeMysqlSignedSessionValidityServices as makeSignedSessionValidityServices,
  makeMysqlStatefulSessionServices as makeStatefulSessionServices,
} from "./drizzle/mysql-sessions";

export {
  coordinateMysqlProofPersistence as coordinateProofPersistence,
  makeMysqlProofPersistenceServices as makeProofPersistenceServices,
} from "./drizzle/mysql-proofs";

export {
  coordinateMysqlPasswordPersistence as coordinatePasswordPersistence,
  coordinateMysqlPasswordRegistration as coordinatePasswordRegistration,
  makeMysqlPasswordPersistenceServices as makePasswordPersistenceServices,
  makeMysqlPasswordRegistrationServices as makePasswordRegistrationServices,
} from "./drizzle/mysql-passwords";

export {
  coordinateMysqlEmailAddress as coordinateEmailAddress,
  coordinateMysqlEmailRegistration as coordinateEmailRegistration,
  makeMysqlEmailAddressServices as makeEmailAddressServices,
  makeMysqlEmailRegistrationServices as makeEmailRegistrationServices,
  makeMysqlEmailSignInServices as makeEmailSignInServices,
} from "./drizzle/mysql-emails";

export const commitMode = "interactive" as const;

export {
  makeMysqlSessionStepUpServices as makeSessionStepUpServices,
  coordinateMysqlSessionStepUp as coordinateSessionStepUp,
} from "./drizzle/mysql-sessions";

export {
  makeMySqlPasswordPreparedPersistenceServices as makePasswordPreparedPersistenceServices,
  coordinateMySqlPasswordPreparedPersistence as coordinatePasswordPreparedPersistence,
} from "./drizzle/mysql-password-prepared";

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

export {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
} from "./drizzle/mysql-oauth";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/mysql-oauth-connected";

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
} from "./drizzle/mysql-passkeys";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/mysql-totp";

export { makePhonePersistenceServices, coordinatePhonePersistence } from "./drizzle/mysql-phone";

export {
  makeMysqlSubjectProvisioningServices as makeSubjectProvisioningServices,
  makeMysqlExternalIdentityServices as makeExternalIdentityServices,
  makeMysqlIdentityServices as makeIdentityServices,
} from "./drizzle/mysql-identity";

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
