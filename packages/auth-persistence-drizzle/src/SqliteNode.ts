import { makeWithDefaults } from "drizzle-orm/effect-sqlite-node";
import { Layer } from "effect";

import { Database } from "./drizzle/sqlite-node-database";

export const commitMode = "interactive" as const;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

export { Database } from "./drizzle/sqlite-node-database";

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
} from "./drizzle/sqlite-node-sessions";

export {
  coordinateProofPersistence,
  makeProofPersistenceServices,
} from "./drizzle/sqlite-node-proofs";

export {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} from "./drizzle/sqlite-node-passwords";

export {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} from "./drizzle/sqlite-node-emails";

export {
  makePasswordPreparedPersistenceServices,
  coordinatePasswordPreparedPersistence,
} from "./drizzle/sqlite-node-password-prepared";

export {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
} from "./drizzle/sqlite-node-oauth";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/sqlite-node-oauth-connected";

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
} from "./drizzle/sqlite-node-passkeys";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/sqlite-node-totp";

export {
  makePhonePersistenceServices,
  coordinatePhonePersistence,
} from "./drizzle/sqlite-node-phone";

export {
  makeIdentityServices,
  makeSubjectProvisioningServices,
  makeExternalIdentityServices,
} from "./drizzle/sqlite-node-identity";

export { AuthPersistence } from "./internal/sqlite-node-persistence";

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
