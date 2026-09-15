import type { D1Client } from "@effect/sql-d1/D1Client";
export { makeTotpPersistenceServices, coordinateTotpPersistence } from "./drizzle/d1-totp";
import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteD1Database } from "drizzle-orm/effect-d1";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";

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

import {
  makeD1ExternalIdentityServices,
  makeD1IdentityServices,
  makeD1SubjectProvisioningServices,
} from "./drizzle/d1-identity";

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

import { type AuthTables, type D1GeneratedIdentityMapping } from "./drizzle/model";
import {
  makeSqliteAuthServices,
  makeSqliteAuthStoreServices,
  makeSqliteOAuthStateServices,
} from "./drizzle/sqlite";

export {
  makeD1ExternalIdentityServices as makeExternalIdentityServices,
  makeD1SubjectProvisioningServices as makeSubjectProvisioningServices,
  makeSqliteAuthStoreServices as makeAuthStoreServices,
  makeSqliteOAuthStateServices as makeOAuthStateServices,
};

export const commitMode = "batch" as const;

export const makeAuthServices = <
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
>(
  database: EffectSQLiteD1Database<AnyRelations>,
  mapping: AuthTables<C, R, S>,
) => makeSqliteAuthServices(database, mapping);

export const makeIdentityServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  External extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  database: EffectSQLiteD1Database<AnyRelations> & { readonly $client: D1Client },
  mapping: D1GeneratedIdentityMapping<Subject, Identifier, External, Request, NativeId>,
) => makeD1IdentityServices(database, mapping);

export {
  makeD1SessionStepUpServices as makeSessionStepUpServices,
  coordinateD1SessionStepUp as coordinateSessionStepUp,
} from "./drizzle/d1-sessions";

export {
  makeD1PasswordPreparedPersistenceServices as makePasswordPreparedPersistenceServices,
  coordinateD1PasswordPreparedPersistence as coordinatePasswordPreparedPersistence,
} from "./drizzle/d1-password-prepared";

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

import { Effect } from "effect";

import { makeD1OAuthConnectedTarget } from "./drizzle/oauth-connected-drivers";
import type { OAuthD1Mapping } from "./drizzle/oauth-model";

const connectedTarget = makeD1OAuthConnectedTarget<
  EffectSQLiteD1Database<AnyRelations> & { readonly $client: D1Client },
  AnySQLiteTable<{ dialect: "sqlite" }>,
  OAuthD1Mapping
>({ mode: "batch", dialect: "sqlite", locking: false, standaloneGuard: () => Effect.void });

export const {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} = connectedTarget;

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
