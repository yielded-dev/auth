import type { AnyRelations } from "drizzle-orm";
import type { EffectMysql2Database } from "drizzle-orm/effect-mysql2";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core";

import type { AuthTables, IdentityTables } from "./drizzle/model";
import {
  coordinateMysqlAuthStoreTransaction,
  coordinateMysqlAuthTransaction,
  coordinateMysqlOAuthStateTransaction,
  makeMysqlAuthServices,
  makeMysqlAuthStoreServices,
  makeMysqlOAuthStateServices,
} from "./drizzle/mysql";
import {
  makeMysqlExternalIdentityServices,
  makeMysqlIdentityServices,
  makeMysqlSubjectProvisioningServices,
} from "./drizzle/mysql-identity";

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

export {
  coordinateMysqlAuthStoreTransaction as coordinateAuthStoreTransaction,
  coordinateMysqlAuthTransaction as coordinateAuthTransaction,
  coordinateMysqlOAuthStateTransaction as coordinateOAuthStateTransaction,
  makeMysqlAuthStoreServices as makeAuthStoreServices,
  makeMysqlExternalIdentityServices as makeExternalIdentityServices,
  makeMysqlOAuthStateServices as makeOAuthStateServices,
  makeMysqlSubjectProvisioningServices as makeSubjectProvisioningServices,
};

export const commitMode = "interactive" as const;

export const makeAuthServices = <
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
  S extends AnyMySqlTable,
>(
  database: EffectMysql2Database<AnyRelations>,
  mapping: AuthTables<C, R, S>,
) => makeMysqlAuthServices(database, mapping);

export const makeIdentityServices = <
  Subject extends AnyMySqlTable,
  Identifier extends AnyMySqlTable,
  External extends AnyMySqlTable,
  Request extends AnyMySqlTable,
  NativeId,
>(
  database: EffectMysql2Database<AnyRelations>,
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => makeMysqlIdentityServices(database, mapping);

export {
  makeMysqlSessionStepUpServices as makeSessionStepUpServices,
  coordinateMysqlSessionStepUp as coordinateSessionStepUp,
} from "./drizzle/mysql-sessions";

export {
  makeMySqlPasswordPreparedPersistenceServices as makePasswordPreparedPersistenceServices,
  coordinateMySqlPasswordPreparedPersistence as coordinatePasswordPreparedPersistence,
} from "./drizzle/mysql-password-prepared";

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

import { makeOAuthTarget } from "./drizzle/oauth-drivers";
import { mysqlOAuthTransaction } from "./drizzle/oauth-mysql";
import { sqlClientOAuthStandaloneGuard } from "./drizzle/oauth-target";

const oauthTarget = makeOAuthTarget<
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>({
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  transaction: mysqlOAuthTransaction,
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
import { unavailable as passkeyUnavailable } from "./drizzle/passkey-state";
import { sqlClientPasskeyStandaloneGuard } from "./drizzle/passkey-target";
import { mysqlTransaction } from "./drizzle/transaction-mysql";

const passkeyTarget = makePasskeyTarget<
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>({
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientPasskeyStandaloneGuard,
  transaction: (database, body) => mysqlTransaction(passkeyUnavailable, database, body),
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

import { unavailable as totpUnavailable } from "./drizzle/totp-state";
import { makeTotpTarget, sqlClientTotpStandaloneGuard } from "./drizzle/totp-target";

const totpTarget = makeTotpTarget<
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>({
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientTotpStandaloneGuard,
  transaction: (database, body) => mysqlTransaction(totpUnavailable, database, body),
});

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = totpTarget;

import { unavailable as phoneUnavailable } from "./drizzle/phone-state";
import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./drizzle/phone-target";

const phoneTarget = makePhoneTarget<
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>({
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
  transaction: (database, body) => mysqlTransaction(phoneUnavailable, database, body),
});

export const { makePhonePersistenceServices, coordinatePhonePersistence } = phoneTarget;
