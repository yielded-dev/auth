export { OAuthProxyPersistence } from "./internal/drizzle-sqlite-oauth-proxy";

import { SqliteClient } from "@effect/sql-sqlite-do/SqliteClient";
import { NativeDatabase, PersistenceConfigurationError } from "@yielded/auth-persistence/Adapter";
import type { AnyRelations } from "drizzle-orm";
import { makeWithDefaults } from "drizzle-orm/effect-sqlite-do";

import { type DatabaseValue, makeDatabase } from "./drizzle/sqlite-do-database";
export { type DatabaseValue, type Transaction, makeDatabase } from "./drizzle/sqlite-do-database";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Context, Effect, Layer } from "effect";

import { nativeDatabase } from "./drizzle/native-database";

/** The application-owned Drizzle queries with Effect SQL transaction ownership. */
export class Database extends Context.Service<Database, DatabaseValue<AnyRelations>>()(
  "effect-auth/persistence-drizzle/SqliteDo/Database",
) {}

/** Construct Drizzle with asynchronous transactions owned by Effect SQL. */
export const databaseLayer = Layer.effect(
  Database,
  Effect.gen(function* () {
    const client = yield* SqliteClient;
    const storage = client.config.storage;

    if (storage === undefined)
      return yield* PersistenceConfigurationError.make({
        reason: "SqliteDo requires a SQL client configured with Durable Object storage",
      });

    return yield* makeDatabase(yield* makeWithDefaults({ storage }));
  }),
);

import { sqlClientEmailStandaloneGuard } from "./drizzle/email-target";
import type {
  ExternalIdentityTables,
  IdentityTables,
  SubjectProvisioningTables,
} from "./drizzle/model";
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

const sessionTarget = makeSqliteSessionTarget<Database, DatabaseValue<AnyRelations>>(
  Database,
  (service) => sqliteSessionConfiguration("interactive", sqlClientSessionStandaloneGuard(service)),
);

const proofTarget = makeSqliteProofTarget<Database, DatabaseValue<AnyRelations>>(
  Database,
  (service) => sqliteProofConfiguration("interactive", sqlClientProofStandaloneGuard(service)),
);

const passwordTarget = makeSqlitePasswordTarget<Database, DatabaseValue<AnyRelations>>(
  Database,
  (service) =>
    sqlitePasswordConfiguration(
      "interactive",
      sqlClientPasswordStandaloneGuard(service),
      sqlClientProofStandaloneGuard(service),
    ),
);

const emailTarget = makeSqliteEmailTarget<Database, DatabaseValue<AnyRelations>>(
  Database,
  (service) =>
    sqliteEmailConfiguration(
      "interactive",
      sqlClientEmailStandaloneGuard(service),
      sqlClientProofStandaloneGuard(service),
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

import { makeSqlitePasswordPreparedTarget } from "./drizzle/sqlite-password-prepared";

const passwordPreparedTarget = makeSqlitePasswordPreparedTarget<
  Database,
  DatabaseValue<AnyRelations>
>(Database, (service) =>
  sqlitePasswordConfiguration(
    "interactive",
    sqlClientPasswordStandaloneGuard(service),
    sqlClientProofStandaloneGuard(service),
  ),
);

export const { makePasswordPreparedPersistenceServices, coordinatePasswordPreparedPersistence } =
  passwordPreparedTarget;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

import { makeOAuthTarget } from "./drizzle/oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./drizzle/oauth-target";

const oauthTarget = makeOAuthTarget<
  Database,
  DatabaseValue<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
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
  Database,
  DatabaseValue<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
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
  Database,
  DatabaseValue<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientTotpStandaloneGuard,
});

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = totpTarget;

import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./drizzle/phone-target";

const phoneTarget = makePhoneTarget<
  Database,
  DatabaseValue<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>
>(Database, {
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
});

export const { makePhonePersistenceServices, coordinatePhonePersistence } = phoneTarget;
