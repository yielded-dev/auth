import { OAuthStateDecisions } from "@yielded/auth/OAuth";
import { AuthStoreDecisions } from "@yielded/auth/Persistence";
import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Context, Effect } from "effect";
import type { SqlError } from "effect/unstable/sql/SqlError";

import type {
  AuthStoreTables,
  AuthTables,
  ExternalIdentityTables,
  IdentityTables,
  OAuthStateTables,
  SubjectProvisioningTables,
} from "./drizzle/model";
import {
  makeSqliteAuthServices,
  makeSqliteAuthStoreServices,
  makeSqliteOAuthStateServices,
} from "./drizzle/sqlite";
import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./drizzle/sqlite-emails";
import {
  makeSqliteExternalIdentityServices,
  makeSqliteIdentityServices,
  makeSqliteSubjectProvisioningServices,
} from "./drizzle/sqlite-identity";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./drizzle/sqlite-passwords";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./drizzle/sqlite-proofs";
import { makeSqliteSessionTarget, sqliteSessionConfiguration } from "./drizzle/sqlite-sessions";
import type { SuppliedService } from "./drizzle/SuppliedService";

const sessionTarget = makeSqliteSessionTarget<EffectSQLiteDoDatabase<AnyRelations>, true>(
  sqliteSessionConfiguration("synchronous", Effect.void),
);

const proofTarget = makeSqliteProofTarget<EffectSQLiteDoDatabase<AnyRelations>, true>(
  sqliteProofConfiguration("synchronous", Effect.void),
);

const passwordTarget = makeSqlitePasswordTarget<EffectSQLiteDoDatabase<AnyRelations>, true>(
  sqlitePasswordConfiguration("synchronous", Effect.void, Effect.void),
);

const emailTarget = makeSqliteEmailTarget<EffectSQLiteDoDatabase<AnyRelations>, true>(
  sqliteEmailConfiguration("synchronous", Effect.void, Effect.void),
);

/**
 * Email mutations must own their outer transactionSync. Arbitrary raw Drizzle
 * nesting is not detectable; owner bodies and mapping allocators stay runSync-compatible.
 */
export const {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} = emailTarget;

/**
 * Password mutations and registration must own their outer transactionSync.
 * Arbitrary raw Drizzle nesting is not detectable; owner bodies must remain
 * runSync-compatible. Detectable Effect commit scopes are rejected pre-write.
 */
export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = passwordTarget;

/**
 * Proof mutations and coordinateProofPersistence must own their outermost
 * transactionSync call. The installed driver cannot detect an arbitrary raw
 * Drizzle outer transaction; calling either boundary from one is unsupported.
 * The owner body must remain runSync-compatible.
 */
export const { coordinateProofPersistence, makeProofPersistenceServices } = proofTarget;

/**
 * Session mutation methods and coordinate* functions must own their outermost
 * transactionSync call. The installed Drizzle driver exposes no context marker
 * for an arbitrary raw outer database.transaction call, so invoking either
 * boundary from one is unsupported and cannot be detected. Detectable Effect
 * commit scopes are rejected before writes.
 */
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

export const commitMode = "synchronous" as const;

export const makeAuthStoreServices = <C extends AnySQLiteTable, R extends AnySQLiteTable>(
  database: EffectSQLiteDoDatabase<AnyRelations>,
  mapping: AuthStoreTables<C, R>,
) => makeSqliteAuthStoreServices(database, mapping);

export const makeOAuthStateServices = <S extends AnySQLiteTable>(
  database: EffectSQLiteDoDatabase<AnyRelations>,
  mapping: OAuthStateTables<S>,
) => makeSqliteOAuthStateServices(database, mapping);

export const makeAuthServices = <
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
>(
  database: EffectSQLiteDoDatabase<AnyRelations>,
  mapping: AuthTables<C, R, S>,
) => makeSqliteAuthServices(database, mapping);

type TransactionOf<D extends EffectSQLiteDoDatabase<AnyRelations>> = Parameters<
  Parameters<D["transaction"]>[0]
>[0];

export function coordinateAuthStoreTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  A,
  E,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: AuthStoreTables<C, R>; readonly transaction?: never },
  body: Effect.Effect<A, E, NoInfer<AuthStoreDecisions>>,
): Effect.Effect<A, E | DatabaseError | SqlError, DatabaseRequirements>;

export function coordinateAuthStoreTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  A,
  E,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: AuthStoreTables<C, R>;
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, NoInfer<AuthStoreDecisions | TxId>>,
): Effect.Effect<A, E | DatabaseError | SqlError, DatabaseRequirements>;

export function coordinateAuthStoreTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  A,
  E,
  Requirements,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: AuthStoreTables<C, R>;
    readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
) {
  return Effect.flatMap(acquire, (database) =>
    database.transaction<A, E, Exclude<Requirements, AuthStoreDecisions>>((transaction) => {
      const decisions = makeSqliteAuthStoreServices(transaction, options.mapping).decisions;
      const provided = Context.make(AuthStoreDecisions, decisions);
      const work = Effect.provideContext(body, provided);

      return options.transaction === undefined
        ? work
        : Effect.provideService(
            work,
            options.transaction,
            options.transaction.of(transaction as TransactionOf<D>),
          );
    }),
  );
}

export function coordinateOAuthStateTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  S extends AnySQLiteTable,
  A,
  E,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: OAuthStateTables<S>; readonly transaction?: never },
  body: Effect.Effect<A, E, NoInfer<OAuthStateDecisions>>,
): Effect.Effect<A, E | DatabaseError | SqlError, DatabaseRequirements>;

export function coordinateOAuthStateTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  S extends AnySQLiteTable,
  A,
  E,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: OAuthStateTables<S>;
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, NoInfer<OAuthStateDecisions | TxId>>,
): Effect.Effect<A, E | DatabaseError | SqlError, DatabaseRequirements>;

export function coordinateOAuthStateTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  S extends AnySQLiteTable,
  A,
  E,
  Requirements,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: OAuthStateTables<S>;
    readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
) {
  return Effect.flatMap(acquire, (database) =>
    database.transaction<A, E, Exclude<Requirements, OAuthStateDecisions>>((transaction) => {
      const decisions = makeSqliteOAuthStateServices(transaction, options.mapping).decisions;
      const provided = Context.make(OAuthStateDecisions, decisions);
      const work = Effect.provideContext(body, provided);

      return options.transaction === undefined
        ? work
        : Effect.provideService(
            work,
            options.transaction,
            options.transaction.of(transaction as TransactionOf<D>),
          );
    }),
  );
}

/**
 * Supported composition boundary for Durable Objects. The owner must return
 * decisions as values and translate rejection only after this root
 * transactionSync commit. Its body may contain only runSync-compatible Effects;
 * the installed driver rejects suspension and rolls back. Owner failure rolls
 * back synchronously, so no retry is performed inside this boundary.
 */
export function coordinateAuthTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
  A,
  E,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: AuthTables<C, R, S>; readonly transaction?: never },
  body: Effect.Effect<A, E, NoInfer<AuthStoreDecisions | OAuthStateDecisions>>,
): Effect.Effect<A, E | DatabaseError | SqlError, DatabaseRequirements>;

export function coordinateAuthTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
  A,
  E,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: AuthTables<C, R, S>;
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, NoInfer<AuthStoreDecisions | OAuthStateDecisions | TxId>>,
): Effect.Effect<A, E | DatabaseError | SqlError, DatabaseRequirements>;

export function coordinateAuthTransaction<
  D extends EffectSQLiteDoDatabase<AnyRelations>,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
  A,
  E,
  Requirements,
  DatabaseError,
  DatabaseRequirements,
  TxId,
  TxShape,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: {
    readonly mapping: AuthTables<C, R, S>;
    readonly transaction?: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
) {
  return Effect.flatMap(acquire, (database) =>
    database.transaction<A, E, Exclude<Requirements, AuthStoreDecisions | OAuthStateDecisions>>(
      (transaction) => {
        const decisions = makeSqliteAuthServices(transaction, options.mapping).decisions;

        const provided = Context.make(AuthStoreDecisions, decisions).pipe(
          Context.add(OAuthStateDecisions, decisions),
        );

        const work = Effect.provideContext(body, provided);

        return options.transaction === undefined
          ? work
          : Effect.provideService(
              work,
              options.transaction,
              options.transaction.of(transaction as TransactionOf<D>),
            );
      },
    ),
  );
}

export const makeIdentityServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  External extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  database: EffectSQLiteDoDatabase<AnyRelations>,
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => makeSqliteIdentityServices(database, mapping, "synchronous");

export const makeSubjectProvisioningServices = <
  Subject extends AnySQLiteTable,
  Identifier extends AnySQLiteTable,
  Request extends AnySQLiteTable,
  NativeId,
>(
  database: EffectSQLiteDoDatabase<AnyRelations>,
  mapping: SubjectProvisioningTables<Subject, Identifier, Request, NativeId>,
) => makeSqliteSubjectProvisioningServices(database, mapping, "synchronous");

export const makeExternalIdentityServices = <
  Subject extends AnySQLiteTable,
  External extends AnySQLiteTable,
  NativeId,
>(
  database: EffectSQLiteDoDatabase<AnyRelations>,
  mapping: ExternalIdentityTables<Subject, External, NativeId>,
) => makeSqliteExternalIdentityServices(database, mapping);

import { makeSqlitePasswordPreparedTarget } from "./drizzle/sqlite-password-prepared";

const passwordPreparedTarget = makeSqlitePasswordPreparedTarget<
  EffectSQLiteDoDatabase<AnyRelations>,
  true
>(sqlitePasswordConfiguration("synchronous", Effect.void, Effect.void));

export const { makePasswordPreparedPersistenceServices, coordinatePasswordPreparedPersistence } =
  passwordPreparedTarget;

export { passwordPreparedPersistenceLayer } from "./drizzle/password-prepared-target";

import { makeOAuthTarget } from "./drizzle/oauth-drivers";

const oauthTarget = makeOAuthTarget<
  EffectSQLiteDoDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>,
  true
>({
  mode: "synchronous",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: () => Effect.void,
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

const passkeyTarget = makePasskeyTarget<
  EffectSQLiteDoDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>,
  unknown,
  true
>({
  mode: "synchronous",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: () => Effect.void,
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

import { makeTotpTarget } from "./drizzle/totp-target";

const totpTarget = makeTotpTarget<
  EffectSQLiteDoDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>,
  unknown,
  true
>({
  mode: "synchronous",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: () => Effect.void,
});

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = totpTarget;

import { makePhoneTarget } from "./drizzle/phone-target";

const phoneTarget = makePhoneTarget<
  EffectSQLiteDoDatabase<AnyRelations>,
  AnySQLiteTable<{ dialect: "sqlite" }>,
  unknown,
  true
>({
  mode: "synchronous",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: () => Effect.void,
});

export const { makePhonePersistenceServices, coordinatePhonePersistence } = phoneTarget;
