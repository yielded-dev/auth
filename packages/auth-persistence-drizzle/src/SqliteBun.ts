import { makeWithDefaults } from "drizzle-orm/effect-sqlite-bun";
import { Layer } from "effect";

import { Database } from "./drizzle/sqlite-bun-database";

export const commitMode = "interactive" as const;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

export { Database } from "./drizzle/sqlite-bun-database";

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
} from "./drizzle/sqlite-bun-sessions";

export {
  coordinateProofPersistence,
  makeProofPersistenceServices,
} from "./drizzle/sqlite-bun-proofs";

export {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} from "./drizzle/sqlite-bun-passwords";

export {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} from "./drizzle/sqlite-bun-emails";

export {
  makePasswordPreparedPersistenceServices,
  coordinatePasswordPreparedPersistence,
} from "./drizzle/sqlite-bun-password-prepared";

export {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
} from "./drizzle/sqlite-bun-oauth";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/sqlite-bun-oauth-connected";

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
} from "./drizzle/sqlite-bun-passkeys";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/sqlite-bun-totp";

export {
  makePhonePersistenceServices,
  coordinatePhonePersistence,
} from "./drizzle/sqlite-bun-phone";

export {
  makeIdentityServices,
  makeSubjectProvisioningServices,
  makeExternalIdentityServices,
} from "./drizzle/sqlite-bun-identity";

export { AuthPersistence } from "./internal/sqlite-bun-persistence";

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
