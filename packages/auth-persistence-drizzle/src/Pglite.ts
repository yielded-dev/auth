import { makeWithDefaults } from "drizzle-orm/effect-pglite";
import { Layer } from "effect";

import { Database } from "./drizzle/pg-database";

export { Database } from "./drizzle/pg-database";

export {
  coordinatePgAuthenticationAuthority as coordinateAuthenticationAuthority,
  coordinatePgPendingAuthentication as coordinatePendingAuthentication,
  coordinatePgSignedSessionValidity as coordinateSignedSessionValidity,
  coordinatePgStatefulSessions as coordinateStatefulSessions,
  makePgAuthenticationAuthorityServices as makeAuthenticationAuthorityServices,
  makePgPendingAuthenticationServices as makePendingAuthenticationServices,
  makePgSignedSessionValidityServices as makeSignedSessionValidityServices,
  makePgStatefulSessionServices as makeStatefulSessionServices,
} from "./drizzle/pg-sessions";

export {
  coordinatePgProofPersistence as coordinateProofPersistence,
  makePgProofPersistenceServices as makeProofPersistenceServices,
} from "./drizzle/pg-proofs";

export {
  coordinatePgPasswordPersistence as coordinatePasswordPersistence,
  coordinatePgPasswordRegistration as coordinatePasswordRegistration,
  makePgPasswordPersistenceServices as makePasswordPersistenceServices,
  makePgPasswordRegistrationServices as makePasswordRegistrationServices,
} from "./drizzle/pg-passwords";

export {
  coordinatePgEmailAddress as coordinateEmailAddress,
  coordinatePgEmailRegistration as coordinateEmailRegistration,
  makePgEmailAddressServices as makeEmailAddressServices,
  makePgEmailRegistrationServices as makeEmailRegistrationServices,
  makePgEmailSignInServices as makeEmailSignInServices,
} from "./drizzle/pg-emails";

export const commitMode = "interactive" as const;

export {
  makePgSessionStepUpServices as makeSessionStepUpServices,
  coordinatePgSessionStepUp as coordinateSessionStepUp,
} from "./drizzle/pg-sessions";

export {
  makePgPasswordPreparedPersistenceServices as makePasswordPreparedPersistenceServices,
  coordinatePgPasswordPreparedPersistence as coordinatePasswordPreparedPersistence,
} from "./drizzle/pg-password-prepared";

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
} from "./drizzle/pg-oauth";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/pg-oauth-connected";

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
} from "./drizzle/pg-passkeys";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/pg-totp";

export { makePhonePersistenceServices, coordinatePhonePersistence } from "./drizzle/pg-phone";

export {
  makePgSubjectProvisioningServices as makeSubjectProvisioningServices,
  makePgExternalIdentityServices as makeExternalIdentityServices,
  makePgIdentityServices as makeIdentityServices,
} from "./drizzle/pg-identity";

export { AuthPersistence } from "./internal/pglite-persistence";

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
