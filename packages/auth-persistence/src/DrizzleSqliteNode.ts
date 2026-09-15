import type { AnyRelations } from "drizzle-orm";
import { type EffectSQLiteNodeDatabase, makeWithDefaults } from "drizzle-orm/effect-sqlite-node";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Effect } from "effect";

import type {
  AuthStoreTables,
  AuthTables,
  ExternalIdentityTables,
  IdentityTables,
  OAuthStateTables,
  SubjectProvisioningTables,
} from "./drizzle/model";
import {
  coordinateSqliteAuthStoreTransaction,
  coordinateSqliteAuthTransaction,
  coordinateSqliteOAuthStateTransaction,
  makeSqliteAuthServices,
  makeSqliteAuthStoreServices,
  makeSqliteOAuthStateServices,
} from "./drizzle/sqlite";

export {
  coordinateSqliteAuthStoreTransaction as coordinateAuthStoreTransaction,
  coordinateSqliteAuthTransaction as coordinateAuthTransaction,
  coordinateSqliteOAuthStateTransaction as coordinateOAuthStateTransaction,
};

import { sqlClientEmailStandaloneGuard } from "./drizzle/email-target";
import { sqlClientPasswordStandaloneGuard } from "./drizzle/password-target";
import { sqlClientProofStandaloneGuard } from "./drizzle/proof-target";
import { sqlClientSessionStandaloneGuard } from "./drizzle/session-target";
import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./drizzle/sqlite-emails";
import {
  makeSqliteExternalIdentityServices,
  makeSqliteIdentityServices,
  makeSqliteSubjectProvisioningServices,
} from "./drizzle/sqlite-identity";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./drizzle/sqlite-passwords";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./drizzle/sqlite-proofs";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./drizzle/sqlite-sessions";

const sessionTarget = makeSqliteSessionTarget<EffectSQLiteNodeDatabase<AnyRelations>>((database) =>
  sqliteSessionConfiguration("interactive", sqlClientSessionStandaloneGuard(database)),
);

const proofTarget = makeSqliteProofTarget<EffectSQLiteNodeDatabase<AnyRelations>>((database) =>
  sqliteProofConfiguration("interactive", sqlClientProofStandaloneGuard(database)),
);

const passwordTarget = makeSqlitePasswordTarget<EffectSQLiteNodeDatabase<AnyRelations>>(
  (database) =>
    sqlitePasswordConfiguration(
      "interactive",
      sqlClientPasswordStandaloneGuard(database),
      sqlClientProofStandaloneGuard(database),
    ),
);

const emailTarget = makeSqliteEmailTarget<EffectSQLiteNodeDatabase<AnyRelations>>((database) =>
  sqliteEmailConfiguration(
    "interactive",
    sqlClientEmailStandaloneGuard(database),
    sqlClientProofStandaloneGuard(database),
  ),
);

export const {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} = emailTarget;

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

export const makeAuthStoreServices = <C extends AnySQLiteTable, R extends AnySQLiteTable>(
  database: EffectSQLiteNodeDatabase<AnyRelations>,
  mapping: AuthStoreTables<C, R>,
) => makeSqliteAuthStoreServices(database, mapping);

export const makeOAuthStateServices = <S extends AnySQLiteTable>(
  database: EffectSQLiteNodeDatabase<AnyRelations>,
  mapping: OAuthStateTables<S>,
) => makeSqliteOAuthStateServices(database, mapping);

export const makeAuthServices = <
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
>(
  database: EffectSQLiteNodeDatabase<AnyRelations>,
  mapping: AuthTables<C, R, S>,
) => makeSqliteAuthServices(database, mapping);

export const makeIdentityServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  External extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  database: EffectSQLiteNodeDatabase<AnyRelations>,
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => makeSqliteIdentityServices(database, mapping, "interactive");

export const makeSubjectProvisioningServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  database: EffectSQLiteNodeDatabase<AnyRelations>,
  mapping: SubjectProvisioningTables<Subject, Identifier, Request, NativeId>,
) => makeSqliteSubjectProvisioningServices(database, mapping, "interactive");

export const makeExternalIdentityServices = <
  Subject extends AnySQLiteTable,
  External extends AnySQLiteTable,
  NativeId,
>(
  database: EffectSQLiteNodeDatabase<AnyRelations>,
  mapping: ExternalIdentityTables<Subject, External, NativeId>,
) => makeSqliteExternalIdentityServices(database, mapping);

import { makeSqlitePasswordPreparedTarget } from "./drizzle/sqlite-password-prepared";

const passwordPreparedTarget = makeSqlitePasswordPreparedTarget<
  EffectSQLiteNodeDatabase<AnyRelations>
>((database) =>
  sqlitePasswordConfiguration(
    "interactive",
    sqlClientPasswordStandaloneGuard(database),
    sqlClientProofStandaloneGuard(database),
  ),
);

export const { makePasswordPreparedPersistenceServices, coordinatePasswordPreparedPersistence } =
  passwordPreparedTarget;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

import { makeOAuthTarget } from "./drizzle/oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./drizzle/oauth-target";

const oauthTarget = makeOAuthTarget<
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>({
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
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
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>({
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
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

const totpTarget = makeTotpTarget<
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>({
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientTotpStandaloneGuard,
});

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = totpTarget;

import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./drizzle/phone-target";

const phoneTarget = makePhoneTarget<
  EffectSQLiteNodeDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>({
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
});

export const { makePhonePersistenceServices, coordinatePhonePersistence } = phoneTarget;

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
