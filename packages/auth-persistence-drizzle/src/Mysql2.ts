import type { AnyRelations } from "drizzle-orm";
import { type EffectMysql2Database, makeWithDefaults } from "drizzle-orm/effect-mysql2";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core";
import { Layer } from "effect";

import type {
  IdentityTables,
  SubjectProvisioningTables,
  ExternalIdentityTables,
} from "./drizzle/model";
import { Database } from "./drizzle/mysql-database";
import {
  makeMysqlExternalIdentityServices,
  makeMysqlIdentityServices,
  makeMysqlSubjectProvisioningServices,
} from "./drizzle/mysql-identity";

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

import { makeProofTarget } from "./drizzle/proof-drivers";

export const { coordinateProofPersistence, makeProofPersistenceServices } = makeProofTarget(
  Database,
  { mode: "native", dialect: "mysql" },
);

import { makePasswordTarget } from "./drizzle/password-drivers";

export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = makePasswordTarget(Database, { mode: "native", dialect: "mysql" });

import { makeEmailTarget } from "./drizzle/email-drivers";

export const {
  makeEmailSignInServices,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  coordinateEmailAddress,
  coordinateEmailRegistration,
} = makeEmailTarget(Database, { mode: "native", dialect: "mysql" });

export const makeSubjectProvisioningServices = <
  Subject extends AnyMySqlTable,
  Identifier extends AnyMySqlTable,
  Request extends AnyMySqlTable,
  NativeId,
>(
  mapping: SubjectProvisioningTables<Subject, Identifier, Request, NativeId>,
) => makeMysqlSubjectProvisioningServices(mapping);

export const makeExternalIdentityServices = <
  Subject extends AnyMySqlTable,
  External extends AnyMySqlTable,
  NativeId,
>(
  mapping: ExternalIdentityTables<Subject, External, NativeId>,
) => makeMysqlExternalIdentityServices(mapping);

export const commitMode = "interactive" as const;

export const makeIdentityServices = <
  Subject extends AnyMySqlTable,
  Identifier extends AnyMySqlTable,
  External extends AnyMySqlTable,
  Request extends AnyMySqlTable,
  NativeId,
>(
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => makeMysqlIdentityServices(mapping);

export {
  makeMysqlSessionStepUpServices as makeSessionStepUpServices,
  coordinateMysqlSessionStepUp as coordinateSessionStepUp,
} from "./drizzle/mysql-sessions";

import { makeOAuthTarget } from "./drizzle/oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./drizzle/oauth-target";

const oauthTarget = makeOAuthTarget<
  Database,
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>(Database, {
  mode: "interactive",
  dialect: "mysql",
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
import { sqlClientPasskeyStandaloneGuard } from "./drizzle/passkey/target";
import { mysqlTransaction } from "./drizzle/transaction-mysql";

const passkeyTarget = makePasskeyTarget<
  Database,
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>(Database, {
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientPasskeyStandaloneGuard,
});

export const {
  makePasskeyCredentialServices,
  makePasskeyPersistenceServices,
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
  Database,
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>(Database, {
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientTotpStandaloneGuard,
  transaction: (database, body) => mysqlTransaction(totpUnavailable, database, body),
});

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = totpTarget;

import { makePhoneTarget } from "./drizzle/phone-drivers";

export const { makePhonePersistenceServices, coordinatePhonePersistence } = makePhoneTarget(
  Database,
  { mode: "native", dialect: "mysql" },
);

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));
