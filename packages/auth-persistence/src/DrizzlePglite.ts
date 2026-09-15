import type { AnyRelations } from "drizzle-orm";
import { type EffectPgDatabase, makeWithDefaults } from "drizzle-orm/effect-pglite";
import type { AnyPgTable } from "drizzle-orm/pg-core";
import { Effect } from "effect";

import type { AuthTables, IdentityTables } from "./drizzle/model";
import {
  coordinatePgAuthStoreTransaction,
  coordinatePgAuthTransaction,
  coordinatePgOAuthStateTransaction,
  makePgAuthServices,
  makePgAuthStoreServices,
  makePgExternalIdentityServices,
  makePgIdentityServices,
  makePgOAuthStateServices,
  makePgSubjectProvisioningServices,
} from "./drizzle/pg";

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

export {
  coordinatePgAuthStoreTransaction as coordinateAuthStoreTransaction,
  coordinatePgAuthTransaction as coordinateAuthTransaction,
  coordinatePgOAuthStateTransaction as coordinateOAuthStateTransaction,
  makePgAuthStoreServices as makeAuthStoreServices,
  makePgExternalIdentityServices as makeExternalIdentityServices,
  makePgOAuthStateServices as makeOAuthStateServices,
  makePgSubjectProvisioningServices as makeSubjectProvisioningServices,
};

export const commitMode = "interactive" as const;

export const makeAuthServices = <C extends AnyPgTable, R extends AnyPgTable, S extends AnyPgTable>(
  database: EffectPgDatabase<AnyRelations>,
  mapping: AuthTables<C, R, S>,
) => makePgAuthServices(database, mapping);

export const makeIdentityServices = <
  Subject extends AnyPgTable,
  Identifier extends AnyPgTable,
  External extends AnyPgTable,
  Request extends AnyPgTable,
  NativeId,
>(
  database: EffectPgDatabase<AnyRelations>,
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => makePgIdentityServices(database, mapping);

export {
  makePgSessionStepUpServices as makeSessionStepUpServices,
  coordinatePgSessionStepUp as coordinateSessionStepUp,
} from "./drizzle/pg-sessions";

export {
  makePgPasswordPreparedPersistenceServices as makePasswordPreparedPersistenceServices,
  coordinatePgPasswordPreparedPersistence as coordinatePasswordPreparedPersistence,
} from "./drizzle/pg-password-prepared";

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

import { makeOAuthTarget } from "./drizzle/oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./drizzle/oauth-target";

const oauthTarget = makeOAuthTarget<EffectPgDatabase<AnyRelations>, AnyPgTable<{ dialect: "pg" }>>({
  mode: "interactive",
  dialect: "pg",
  locking: true,
  standaloneGuard: sqlClientOAuthStandaloneGuard,
});

export const {
  makeOAuthAccountsServices,
  makeOAuthSignInServices,
  makeOAuthRegistrationIntentServices,
  makeOAuthRegistrationServices,
  coordinateOAuthRegistration,
  coordinateOAuthSignIn,
  coordinateOAuthRegistrationIntents,
  coordinateOAuthAccounts,
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} = oauthTarget;

import { makePasskeyTarget } from "./drizzle/passkey-drivers";
import { sqlClientPasskeyStandaloneGuard } from "./drizzle/passkey-target";

const passkeyTarget = makePasskeyTarget<
  EffectPgDatabase<AnyRelations>,
  AnyPgTable<{ dialect: "pg" }>
>({
  mode: "interactive",
  dialect: "pg",
  locking: true,
  standaloneGuard: sqlClientPasskeyStandaloneGuard,
});

export const {
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
} = passkeyTarget;

import { makeTotpTarget, sqlClientTotpStandaloneGuard } from "./drizzle/totp-target";

const totpTarget = makeTotpTarget<EffectPgDatabase<AnyRelations>, AnyPgTable<{ dialect: "pg" }>>({
  mode: "interactive",
  dialect: "pg",
  locking: true,
  standaloneGuard: sqlClientTotpStandaloneGuard,
});

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = totpTarget;

import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./drizzle/phone-target";

const phoneTarget = makePhoneTarget<EffectPgDatabase<AnyRelations>, AnyPgTable<{ dialect: "pg" }>>({
  mode: "interactive",
  dialect: "pg",
  locking: true,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
});

export const { makePhonePersistenceServices, coordinatePhonePersistence } = phoneTarget;

import { drizzleMigrationsLayer } from "./internal/drizzle-migrations";
import { postgresPersistence } from "./internal/drizzle-postgres";

export const AuthPersistence = {
  ...postgresPersistence(makeWithDefaults({})),
  migrationsLayer: drizzleMigrationsLayer(
    makeWithDefaults({}),
    Effect.promise(() => import("drizzle-orm/effect-pglite/migrator")).pipe(
      Effect.map((module) => module.migrate),
    ),
  ),
};
