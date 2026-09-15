import { EmailUnavailable } from "@yielded/auth/Email";
import { AuthStoreError } from "@yielded/auth/Errors";
import { PasswordUnavailable } from "@yielded/auth/Password";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import { SessionUnavailable } from "@yielded/auth/Sessions";
import type { AnyRelations } from "drizzle-orm";
import { type EffectLibsqlDatabase, makeWithDefaults } from "drizzle-orm/effect-libsql";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Context, Effect, Option } from "effect";

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

import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./drizzle/sqlite-emails";
import {
  makeSqliteExternalIdentityServices,
  makeSqliteIdentityServices,
  makeSqliteSubjectProvisioningServices,
} from "./drizzle/sqlite-identity";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./drizzle/sqlite-passwords";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./drizzle/sqlite-proofs";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./drizzle/sqlite-sessions";

// @effect/sql-libsql owns a driver-specific transaction context rather than
// SqlClient.transactionService. This tag name is an upstream private detail
// verified against 4.0.0-rc.112 and must be rechecked on driver upgrades;
// Context's string-key identity makes the installed-version guard possible.
const LibsqlTransaction = Context.Service<unknown>(
  "@effect/sql-libsql/LibsqlClient/LibsqlTransaction",
);

const requireStandalone = Effect.serviceOption(LibsqlTransaction).pipe(
  Effect.flatMap(
    Option.match({
      onNone: () => Effect.void,
      onSome: () =>
        AuthStoreError.make({
          message: "Use the decision consume API inside an outer database transaction",
        }),
    }),
  ),
);

const requireStandaloneSession = Effect.serviceOption(LibsqlTransaction).pipe(
  Effect.flatMap(
    Option.match({
      onNone: () => Effect.void,
      onSome: () => SessionUnavailable.make({}),
    }),
  ),
);

const requireStandaloneProof = Effect.serviceOption(LibsqlTransaction).pipe(
  Effect.flatMap(
    Option.match({
      onNone: () => Effect.void,
      onSome: () => ProofUnavailable.make({}),
    }),
  ),
);

const requireStandalonePassword = Effect.serviceOption(LibsqlTransaction).pipe(
  Effect.flatMap(
    Option.match({
      onNone: () => Effect.void,
      onSome: () => PasswordUnavailable.make({}),
    }),
  ),
);

const requireStandaloneEmail = Effect.serviceOption(LibsqlTransaction).pipe(
  Effect.flatMap(
    Option.match({
      onNone: () => Effect.void,
      onSome: () => EmailUnavailable.make({}),
    }),
  ),
);

const sessionTarget = makeSqliteSessionTarget<EffectLibsqlDatabase<AnyRelations>>(
  sqliteSessionConfiguration("interactive", requireStandaloneSession),
);

const proofTarget = makeSqliteProofTarget<EffectLibsqlDatabase<AnyRelations>>(
  sqliteProofConfiguration("interactive", requireStandaloneProof),
);

const passwordTarget = makeSqlitePasswordTarget<EffectLibsqlDatabase<AnyRelations>>(
  sqlitePasswordConfiguration("interactive", requireStandalonePassword, requireStandaloneProof),
);

const emailTarget = makeSqliteEmailTarget<EffectLibsqlDatabase<AnyRelations>>(
  sqliteEmailConfiguration("interactive", requireStandaloneEmail, requireStandaloneProof),
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
  database: EffectLibsqlDatabase<AnyRelations>,
  mapping: AuthStoreTables<C, R>,
) => makeSqliteAuthStoreServices(database, mapping, requireStandalone);

export const makeOAuthStateServices = <S extends AnySQLiteTable>(
  database: EffectLibsqlDatabase<AnyRelations>,
  mapping: OAuthStateTables<S>,
) => makeSqliteOAuthStateServices(database, mapping, requireStandalone);

export const makeAuthServices = <
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
>(
  database: EffectLibsqlDatabase<AnyRelations>,
  mapping: AuthTables<C, R, S>,
) => makeSqliteAuthServices(database, mapping, requireStandalone);

export const makeIdentityServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  External extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  database: EffectLibsqlDatabase<AnyRelations>,
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => makeSqliteIdentityServices(database, mapping, "interactive");

export const makeSubjectProvisioningServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  database: EffectLibsqlDatabase<AnyRelations>,
  mapping: SubjectProvisioningTables<Subject, Identifier, Request, NativeId>,
) => makeSqliteSubjectProvisioningServices(database, mapping, "interactive");

export const makeExternalIdentityServices = <
  Subject extends AnySQLiteTable,
  External extends AnySQLiteTable,
  NativeId,
>(
  database: EffectLibsqlDatabase<AnyRelations>,
  mapping: ExternalIdentityTables<Subject, External, NativeId>,
) => makeSqliteExternalIdentityServices(database, mapping);

import { makeSqlitePasswordPreparedTarget } from "./drizzle/sqlite-password-prepared";

const passwordPreparedTarget = makeSqlitePasswordPreparedTarget<EffectLibsqlDatabase<AnyRelations>>(
  sqlitePasswordConfiguration("interactive", requireStandalonePassword, requireStandaloneProof),
);

export const { makePasswordPreparedPersistenceServices, coordinatePasswordPreparedPersistence } =
  passwordPreparedTarget;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

import { makeOAuthTarget } from "./drizzle/oauth-drivers";
import { sqlClientOAuthStandaloneGuard } from "./drizzle/oauth-target";

const oauthTarget = makeOAuthTarget<
  EffectLibsqlDatabase<AnyRelations>,
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
  EffectLibsqlDatabase<AnyRelations>,
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
  EffectLibsqlDatabase<AnyRelations>,
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
  EffectLibsqlDatabase<AnyRelations>,
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
    Effect.promise(() => import("drizzle-orm/effect-libsql/migrator")).pipe(
      Effect.map((module) => module.migrate),
    ),
  ),
};
