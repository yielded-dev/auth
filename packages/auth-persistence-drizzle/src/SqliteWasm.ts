import { makeWithDefaults } from "drizzle-orm/effect-sqlite-wasm";
import { Layer } from "effect";

import { Database } from "./drizzle/sqlite-wasm-database";

export const commitMode = "interactive" as const;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

export { Database } from "./drizzle/sqlite-wasm-database";

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
} from "./drizzle/sqlite-wasm-sessions";

export {
  coordinateProofPersistence,
  makeProofPersistenceServices,
} from "./drizzle/sqlite-wasm-proofs";

export {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} from "./drizzle/sqlite-wasm-passwords";

export {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} from "./drizzle/sqlite-wasm-emails";

export {
  makePasswordPreparedPersistenceServices,
  coordinatePasswordPreparedPersistence,
} from "./drizzle/sqlite-wasm-password-prepared";

export {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
} from "./drizzle/sqlite-wasm-oauth";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/sqlite-wasm-oauth-connected";

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
} from "./drizzle/sqlite-wasm-passkeys";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/sqlite-wasm-totp";

export {
  makePhonePersistenceServices,
  coordinatePhonePersistence,
} from "./drizzle/sqlite-wasm-phone";

export {
  makeIdentityServices,
  makeSubjectProvisioningServices,
  makeExternalIdentityServices,
} from "./drizzle/sqlite-wasm-identity";

export { AuthPersistence } from "./internal/sqlite-wasm-persistence";

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
