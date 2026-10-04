import { SqliteClient } from "@effect/sql-sqlite-do/SqliteClient";
import { PersistenceConfigurationError } from "@yielded/auth-persistence/Adapter";
import { makeWithDefaults } from "drizzle-orm/effect-sqlite-do";
import { Effect, Layer } from "effect";

import { Database } from "./drizzle/sqlite-do-database";

export const commitMode = "synchronous" as const;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

export { Database } from "./drizzle/sqlite-do-database";

/**
 * Session mutation methods and coordinate* functions must own their outermost
 * transactionSync call. The installed Drizzle driver exposes no context marker
 * for an arbitrary raw outer database.transaction call, so invoking either
 * boundary from one is unsupported and cannot be detected. Detectable Effect
 * commit scopes are rejected before writes.
 */
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
} from "./drizzle/sqlite-do-sessions";

/**
 * Proof mutations and coordinateProofPersistence must own their outermost
 * transactionSync call. The installed driver cannot detect an arbitrary raw
 * Drizzle outer transaction; calling either boundary from one is unsupported.
 * The owner body must remain runSync-compatible.
 */
export {
  coordinateProofPersistence,
  makeProofPersistenceServices,
} from "./drizzle/sqlite-do-proofs";

/**
 * Password mutations and registration must own their outer transactionSync.
 * Arbitrary raw Drizzle nesting is not detectable; owner bodies must remain
 * runSync-compatible. Detectable Effect commit scopes are rejected pre-write.
 */
export {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} from "./drizzle/sqlite-do-passwords";

/**
 * Email mutations must own their outer transactionSync. Arbitrary raw Drizzle
 * nesting is not detectable; owner bodies and mapping allocators stay runSync-compatible.
 */
export {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} from "./drizzle/sqlite-do-emails";

export {
  makePasswordPreparedPersistenceServices,
  coordinatePasswordPreparedPersistence,
} from "./drizzle/sqlite-do-password-prepared";

export {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
} from "./drizzle/sqlite-do-oauth";

export {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} from "./drizzle/sqlite-do-oauth-connected";

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
} from "./drizzle/sqlite-do-passkeys";

export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/sqlite-do-totp";

export {
  makePhonePersistenceServices,
  coordinatePhonePersistence,
} from "./drizzle/sqlite-do-phone";

export {
  makeIdentityServices,
  makeSubjectProvisioningServices,
  makeExternalIdentityServices,
} from "./drizzle/sqlite-do-identity";

/** The SQL-client Layer must configure storage so Drizzle owns transactionSync. */
export const databaseLayer = Layer.effect(
  Database,
  Effect.gen(function* () {
    const client = yield* SqliteClient;
    const storage = client.config.storage;

    if (storage === undefined)
      return yield* PersistenceConfigurationError.make({
        reason:
          "SqliteDo requires a SQL client configured with storage for synchronous transactions",
      });

    return yield* makeWithDefaults({ storage });
  }),
);
