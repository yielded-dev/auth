import type { AnyRelations } from "drizzle-orm";
import {
  EffectSQLiteNodeTransaction as PasskeyTransaction,
  type EffectSQLiteNodeDatabase,
  makeWithDefaults,
} from "drizzle-orm/effect-sqlite-node";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Context, Effect, Layer } from "effect";

import { NativeDatabase, nativeDatabase } from "./drizzle/native-database";

/** The application-owned Drizzle database used to construct persistence services. */
export class Database extends Context.Service<Database, EffectSQLiteNodeDatabase<AnyRelations>>()(
  "effect-auth/persistence-drizzle/SqliteNode/Database",
) {}

/** Construct Drizzle from the driver's SQL-client Layer. */
export const databaseLayer = Layer.effect(Database, makeWithDefaults({}));

import type {
  ExternalIdentityTables,
  IdentityTables,
  SubjectProvisioningTables,
} from "./drizzle/model";
import { makePasswordTarget } from "./drizzle/password-drivers";
import { makeProofTarget } from "./drizzle/proof-drivers";
import { sqlClientSessionStandaloneGuard } from "./drizzle/session-target";
import {
  makeSqliteExternalIdentityServices,
  makeSqliteIdentityServices,
  makeSqliteSubjectProvisioningServices,
} from "./drizzle/sqlite-identity";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./drizzle/sqlite-sessions";

const sessionTarget = makeSqliteSessionTarget<Database, EffectSQLiteNodeDatabase<AnyRelations>>(
  Database,
  (service) => sqliteSessionConfiguration("interactive", sqlClientSessionStandaloneGuard(service)),
);

const proofTarget = makeProofTarget(Database, {
  mode: "native",
  dialect: "sqlite",
  transactionConstructor: PasskeyTransaction,
});

const passwordTarget = makePasswordTarget(Database, {
  mode: "native",
  dialect: "sqlite",
  transactionConstructor: PasskeyTransaction,
});

import { makeEmailTarget } from "./drizzle/email-drivers";

export const {
  makeEmailSignInServices,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  coordinateEmailAddress,
  coordinateEmailRegistration,
} = makeEmailTarget(Database, {
  mode: "native",
  dialect: "sqlite",
  transactionConstructor: PasskeyTransaction,
});

export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = passwordTarget;

export const { coordinateProofPersistence, makeProofPersistenceServices } = proofTarget;

export const {
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
} = sessionTarget;

export const commitMode = "interactive" as const;

export const makeIdentityServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  External extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) =>
  makeSqliteIdentityServices(mapping, "interactive").pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(Database)),
  );

export const makeSubjectProvisioningServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  mapping: SubjectProvisioningTables<Subject, Identifier, Request, NativeId>,
) =>
  makeSqliteSubjectProvisioningServices(mapping, "interactive").pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(Database)),
  );

export const makeExternalIdentityServices = <
  Subject extends AnySQLiteTable,
  External extends AnySQLiteTable,
  NativeId,
>(
  mapping: ExternalIdentityTables<Subject, External, NativeId>,
) =>
  makeSqliteExternalIdentityServices(mapping).pipe(
    Effect.provideServiceEffect(NativeDatabase, nativeDatabase(Database)),
  );

import { makeOAuthTarget } from "./drizzle/oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./drizzle/oauth-target";

const oauthTarget = makeOAuthTarget<
  Database,
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientOAuthStandaloneGuard,
  transactionConstructor: PasskeyTransaction,
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

const passkeyTarget = makePasskeyTarget<
  Database,
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  transactionConstructor: PasskeyTransaction,
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
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

import { makeTotpTarget, sqlClientTotpStandaloneGuard } from "./drizzle/totp-target";

const totpTarget = makeTotpTarget<
  Database,
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientTotpStandaloneGuard,
});

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = totpTarget;

import { makePhoneTarget } from "./drizzle/phone-drivers";

export const { makePhonePersistenceServices, coordinatePhonePersistence } = makePhoneTarget(
  Database,
  { mode: "native", dialect: "sqlite", transactionConstructor: PasskeyTransaction },
);

import { drizzleMigrationsLayer } from "./internal/drizzle-migrations";
import { sqlitePersistence } from "./internal/drizzle-sqlite";

export const AuthPersistence = {
  ...sqlitePersistence(makeWithDefaults({})),
  migrationsLayer: drizzleMigrationsLayer(
    makeWithDefaults({}),
    Effect.promise(() => import("drizzle-orm/effect-sqlite-node/migrator")).pipe(
      Effect.map((module) => module.migrate),
    ),
  ),
};

export { OAuthProxyPersistence } from "./internal/drizzle-sqlite-oauth-proxy";
