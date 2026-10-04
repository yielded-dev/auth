import { makeWithDefaults } from "drizzle-orm/effect-libsql";
import { Layer } from "effect";

import { Database } from "./drizzle/libsql-database";

export const commitMode = "interactive" as const;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

export { Database } from "./drizzle/libsql-database";

export {
  coordinateAuthenticationAuthority,
  coordinatePendingAuthentication,
  coordinateSignedSessionValidity,
  coordinateStatefulSessions,
  makeAuthenticationAuthorityServices,
  makePendingAuthenticationServices,
  makeSessionStepUpServices,
  coordinateSessionStepUp,
  makeSignedSessionValidityServices,
  makeStatefulSessionServices,
} from "./drizzle/libsql-sessions";

export { coordinateProofPersistence, makeProofPersistenceServices } from "./drizzle/libsql-proofs";

export {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} from "./drizzle/libsql-passwords";

export {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} from "./drizzle/libsql-emails";

export {
  makePasswordPreparedPersistenceServices,
  coordinatePasswordPreparedPersistence,
} from "./drizzle/libsql-password-prepared";

export {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
} from "./drizzle/libsql-oauth";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/libsql-oauth-connected";

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
} from "./drizzle/libsql-passkeys";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/libsql-totp";

export { makePhonePersistenceServices, coordinatePhonePersistence } from "./drizzle/libsql-phone";

export {
  makeIdentityServices,
  makeSubjectProvisioningServices,
  makeExternalIdentityServices,
} from "./drizzle/libsql-identity";

export { AuthPersistence } from "./internal/libsql-persistence";

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
