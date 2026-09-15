import { AuthStore, EmailOtpRejected } from "@yielded/auth/AuthStore";
import { AuthRateLimited, AuthStoreError, InvalidRegistration } from "@yielded/auth/Errors";
import {
  ExternalIdentityMutation,
  IdentityConflict,
  IdentityUnavailable,
  SubjectProvisioned,
  type ExternalIdentity,
  SubjectProvisioner,
  type SubjectProvisioningInput,
} from "@yielded/auth/Identity";
import {
  InvalidOAuthState,
  OAuthStateDecisions,
  OAuthStateStore,
  type OAuthState,
} from "@yielded/auth/OAuth";
import { AuthStoreDecisions, reportPersistenceFailure } from "@yielded/auth/Persistence";
import {
  VerifiedEmail,
  type ConsumeChallenge,
  type ConsumeRegistration,
  type NewChallenge,
  type NewRegistration,
  type SubjectId,
  type TokenDigest,
} from "@yielded/auth/Schema";
/* oxlint-disable no-explicit-any -- Drizzle's generic query builders lose the concrete consumer table through a runtime column map. Assertions stay in this adapter. */
import {
  and,
  eq,
  gt,
  lt,
  lte,
  ne,
  or,
  sql,
  type AnyRelations,
  type InferSelectModel,
} from "drizzle-orm";
import type { EffectPgDatabase as PgliteDatabase } from "drizzle-orm/effect-pglite";
import type { EffectPgDatabase as PgDatabase } from "drizzle-orm/effect-postgres";
import { type AnyPgTable, type PgColumn } from "drizzle-orm/pg-core";
import { Cause, Context, DateTime, Duration, Effect, Layer, Schema } from "effect";
import type { SqlError } from "effect/unstable/sql/SqlError";

import {
  column,
  PersistenceMappingError,
  isMappedConstraintConflict,
  provisioningFingerprint,
  requireStandaloneConsume,
  updateValues,
  type AuthTables,
  type AuthStoreTables,
  type ChallengeConsumeDecision,
  type ConsumeDecision,
  type ExternalIdentityTables,
  type IdentityTables,
  type OAuthStateTables,
  type SubjectProvisioningTables,
} from "./model";
import type { SuppliedService } from "./SuppliedService";

type Database = PgDatabase<AnyRelations> | PgliteDatabase<AnyRelations>;
type RuntimeDatabase = PgDatabase<any> & Parameters<typeof requireStandaloneConsume>[0];
type TransactionOf<D extends Database> = Parameters<Parameters<D["transaction"]>[0]>[0];

const storeReadError = () => AuthStoreError.make({ message: "Auth store read failed" });
const storeWriteError = () => AuthStoreError.make({ message: "Auth store write failed" });
const isStoreFailure = Schema.is(AuthStoreError);

const mapStoreFailure =
  (failure: () => AuthStoreError) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, AuthStoreError, R> =>
    reportPersistenceFailure(effect, isStoreFailure).pipe(
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, failure))),
    );

const mapStoreReadFailure = mapStoreFailure(storeReadError);
const mapStoreWriteFailure = mapStoreFailure(storeWriteError);
const identityUnavailable = () => IdentityUnavailable.make();
const isIdentityFailure = Schema.is(Schema.Union([IdentityConflict, IdentityUnavailable]));

const mapIdentityFailure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  reportPersistenceFailure(effect, isIdentityFailure).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(
        Cause.map(cause, (error) => (isIdentityFailure(error) ? error : identityUnavailable())),
      ),
    ),
  );

const selected = <T extends AnyPgTable>(row: unknown): InferSelectModel<T> =>
  row as InferSelectModel<T>;

export const makePgAuthStoreServices = <C extends AnyPgTable, R extends AnyPgTable>(
  database: Database,
  mapping: AuthStoreTables<C, R>,
) => {
  const db = database as RuntimeDatabase;
  const challengeTable = mapping.challenge.table;
  const challengeColumns = mapping.challenge.columns;

  const challenge = {
    challengeId: column(challengeTable, challengeColumns.challengeId),
    tokenDigest: column(challengeTable, challengeColumns.tokenDigest),
    namespace: column(challengeTable, challengeColumns.namespace),
    value: column(challengeTable, challengeColumns.value),
    purpose: column(challengeTable, challengeColumns.purpose),
    otpKeyId: column(challengeTable, challengeColumns.otpKeyId),
    otpDigest: column(challengeTable, challengeColumns.otpDigest),
    issuedAt: column(challengeTable, challengeColumns.issuedAt),
    expiresAt: column(challengeTable, challengeColumns.expiresAt),
    attemptLimit: column(challengeTable, challengeColumns.attemptLimit),
    failedAttempts: column(challengeTable, challengeColumns.failedAttempts),
    consumed: column(challengeTable, challengeColumns.consumed),
  } as const;

  const pgChallenge = challenge as Record<keyof typeof challenge, PgColumn>;
  const registrationTable = mapping.registration.table;
  const registrationColumns = mapping.registration.columns;

  const registration = {
    tokenDigest: column(registrationTable, registrationColumns.tokenDigest),
    expiresAt: column(registrationTable, registrationColumns.expiresAt),
    consumed: column(registrationTable, registrationColumns.consumed),
  } as const;

  const issueChallenge = Effect.fn("DrizzlePgAuthStore.issueChallenge")(function* (
    input: NewChallenge,
  ) {
    const now = yield* DateTime.now;

    const cooldownCutoff = DateTime.mapEpochMillis(
      now,
      (millis) => millis - Duration.toMillis(input.resendCooldown),
    );

    const rows = yield* Effect.suspend(() => {
      const values = mapping.challenge.encodeInsert(input, {
        namespace: mapping.challenge.identifierNamespace,
        failedAttempts: 0,
        consumed: false,
      });

      const nativeNow = mapping.challenge.encodeInstant(now);
      const nativeCutoff = mapping.challenge.encodeInstant(cooldownCutoff);
      const nativeIssuedAt = mapping.challenge.encodeInstant(input.issuedAt);
      const preservedAttempts = sql`case when ${gt(pgChallenge.expiresAt, nativeNow)} then ${pgChallenge.failedAttempts} else 0 end`;

      const update = mapping.challenge.encodeUpdate(input, {
        namespace: mapping.challenge.identifierNamespace,
        failedAttempts: preservedAttempts as any,
        consumed: false,
      });

      return db
        .insert(challengeTable as any)
        .values(values as any)
        .onConflictDoUpdate({
          target: [pgChallenge.namespace, pgChallenge.value, pgChallenge.purpose],
          set: update as any,
          setWhere: and(
            ne(pgChallenge.challengeId, input.challengeId),
            lt(pgChallenge.issuedAt, nativeIssuedAt),
            or(eq(pgChallenge.consumed, true), lte(pgChallenge.issuedAt, nativeCutoff)),
          ),
        })
        .returning();
    }).pipe(mapStoreWriteFailure);

    if (rows.length > 0) return;

    const existing = yield* Effect.suspend(() =>
      db
        .select()
        .from(challengeTable as any)
        .where(
          and(
            eq(pgChallenge.namespace, mapping.challenge.identifierNamespace),
            eq(pgChallenge.value, input.email),
            eq(pgChallenge.purpose, input.purpose),
          ),
        )
        .limit(1),
    ).pipe(mapStoreReadFailure);

    const decoded =
      existing[0] === undefined
        ? undefined
        : yield* Effect.suspend(() => mapping.challenge.decode(selected<C>(existing[0]))).pipe(
            mapStoreReadFailure,
          );

    const retryAfterSeconds =
      decoded === undefined
        ? Math.max(1, Math.ceil(Duration.toMillis(input.resendCooldown) / 1000))
        : Math.max(
            1,
            Math.ceil(
              (DateTime.toEpochMillis(decoded.challenge.issuedAt) +
                Duration.toMillis(input.resendCooldown) -
                DateTime.toEpochMillis(now)) /
                1000,
            ),
          );

    return yield* AuthRateLimited.make({ retryAfterSeconds });
  });

  const consumeChallengeDecision = Effect.fn("DrizzlePgAuthStore.consumeChallengeDecision")(
    function* (
      input: ConsumeChallenge,
    ): Effect.fn.Return<ChallengeConsumeDecision, AuthStoreError> {
      const now = yield* DateTime.now;

      const alternatives = Object.entries(input.otpDigests).map(([keyId, digest]) =>
        and(eq(pgChallenge.otpKeyId, keyId), eq(pgChallenge.otpDigest, digest)),
      );

      const matches = alternatives.length === 0 ? sql<boolean>`false` : or(...alternatives)!;

      const rows = yield* Effect.suspend(() =>
        db
          .update(challengeTable as any)
          .set(
            updateValues<C>([
              [
                challengeColumns.consumed,
                sql`case when ${matches} then true else ${pgChallenge.consumed} end`,
              ],
              [
                challengeColumns.failedAttempts,
                sql`${pgChallenge.failedAttempts} + case when ${matches} then 0 else 1 end`,
              ],
            ]) as any,
          )
          .where(
            and(
              eq(pgChallenge.tokenDigest, input.tokenDigest),
              eq(pgChallenge.consumed, false),
              gt(pgChallenge.expiresAt, mapping.challenge.encodeInstant(now)),
              sql`${pgChallenge.failedAttempts} < ${pgChallenge.attemptLimit}`,
            ),
          )
          .returning(),
      ).pipe(mapStoreWriteFailure);

      if (rows[0] === undefined) {
        return { _tag: "rejected", reason: "missing_challenge" };
      }

      const decoded = yield* Effect.suspend(() =>
        mapping.challenge.decode(selected<C>(rows[0])),
      ).pipe(mapStoreReadFailure);

      if (!decoded.consumed) return { _tag: "rejected", reason: "bad_code" };

      return {
        _tag: "accepted",
        value: VerifiedEmail.make({
          email: decoded.challenge.email,
          purpose: decoded.challenge.purpose,
        }),
      };
    },
  );

  const consumeChallenge = Effect.fn("DrizzlePgAuthStore.consumeChallenge")(function* (
    input: ConsumeChallenge,
  ) {
    yield* requireStandaloneConsume(db);
    const decision = yield* consumeChallengeDecision(input);

    return decision._tag === "accepted"
      ? decision.value
      : yield* EmailOtpRejected.make({ reason: decision.reason });
  });

  const issueRegistration = Effect.fn("DrizzlePgAuthStore.issueRegistration")(function* (
    input: NewRegistration,
  ) {
    yield* Effect.suspend(() =>
      db
        .insert(registrationTable as any)
        .values(mapping.registration.encodeInsert(input, false) as any),
    ).pipe(mapStoreWriteFailure);
  });

  const inspectRegistration = Effect.fn("DrizzlePgAuthStore.inspectRegistration")(function* (
    tokenDigest: TokenDigest,
  ) {
    const now = yield* DateTime.now;

    const rows = yield* Effect.suspend(() =>
      db
        .select()
        .from(registrationTable as any)
        .where(
          and(
            eq(registration.tokenDigest, tokenDigest),
            eq(registration.consumed, false),
            gt(registration.expiresAt, mapping.registration.encodeInstant(now)),
          ),
        )
        .limit(1),
    ).pipe(mapStoreReadFailure);

    if (rows[0] === undefined) return yield* InvalidRegistration.make();

    const decoded = yield* Effect.suspend(() =>
      mapping.registration.decode(selected<R>(rows[0])),
    ).pipe(mapStoreReadFailure);

    return decoded.registration;
  });

  const consumeRegistrationDecision = Effect.fn("DrizzlePgAuthStore.consumeRegistrationDecision")(
    function* (
      input: ConsumeRegistration,
    ): Effect.fn.Return<ConsumeDecision<void>, AuthStoreError> {
      const now = yield* DateTime.now;

      const rows = yield* Effect.suspend(() =>
        db
          .update(registrationTable as any)
          .set(updateValues<R>([[registrationColumns.consumed, true]]) as any)
          .where(
            and(
              eq(registration.tokenDigest, input.tokenDigest),
              eq(registration.consumed, false),
              gt(registration.expiresAt, mapping.registration.encodeInstant(now)),
            ),
          )
          .returning({ consumed: registration.consumed as PgColumn }),
      ).pipe(mapStoreWriteFailure);

      return rows.length === 0 ? { _tag: "rejected" } : { _tag: "accepted", value: undefined };
    },
  );

  const consumeRegistration = Effect.fn("DrizzlePgAuthStore.consumeRegistration")(function* (
    input: ConsumeRegistration,
  ) {
    yield* requireStandaloneConsume(db);
    const decision = yield* consumeRegistrationDecision(input);

    if (decision._tag === "rejected") return yield* InvalidRegistration.make();
  });

  return {
    authStore: AuthStore.of({
      issueChallenge,
      consumeChallenge,
      issueRegistration,
      inspectRegistration,
      consumeRegistration,
    }),
    decisions: {
      consumeChallenge: consumeChallengeDecision,
      consumeRegistration: consumeRegistrationDecision,
    },
  } as const;
};

export const makePgOAuthStateServices = <S extends AnyPgTable>(
  database: Database,
  mapping: OAuthStateTables<S>,
) => {
  const db = database as RuntimeDatabase;
  const stateTable = mapping.oauthState.table;
  const stateColumns = mapping.oauthState.columns;

  const state = {
    stateDigest: column(stateTable, stateColumns.stateDigest),
    expiresAt: column(stateTable, stateColumns.expiresAt),
    consumed: column(stateTable, stateColumns.consumed),
  } as const;

  const issue = Effect.fn("DrizzlePgOAuthStateStore.issue")(function* (input: OAuthState) {
    yield* Effect.suspend(() =>
      db.insert(stateTable as any).values(mapping.oauthState.encodeInsert(input, false) as any),
    ).pipe(mapStoreWriteFailure);
  });

  const consumeDecision = Effect.fn("DrizzlePgOAuthStateStore.consumeDecision")(function* (
    digest: TokenDigest,
  ): Effect.fn.Return<ConsumeDecision<OAuthState>, AuthStoreError> {
    const now = yield* DateTime.now;

    const rows = yield* Effect.suspend(() =>
      db
        .update(stateTable as any)
        .set(updateValues<S>([[stateColumns.consumed, true]]) as any)
        .where(
          and(
            eq(state.stateDigest, digest),
            eq(state.consumed, false),
            gt(state.expiresAt, mapping.oauthState.encodeInstant(now)),
          ),
        )
        .returning(),
    ).pipe(mapStoreWriteFailure);

    if (rows[0] === undefined) return { _tag: "rejected" };

    const decoded = yield* Effect.suspend(() =>
      mapping.oauthState.decode(selected<S>(rows[0])),
    ).pipe(mapStoreReadFailure);

    return { _tag: "accepted", value: decoded.state };
  });

  const consume = Effect.fn("DrizzlePgOAuthStateStore.consume")(function* (digest: TokenDigest) {
    yield* requireStandaloneConsume(db);
    const decision = yield* consumeDecision(digest);

    return decision._tag === "accepted" ? decision.value : yield* InvalidOAuthState.make();
  });

  return {
    oauthStateStore: OAuthStateStore.of({ issue, consume }),
    decisions: { consumeOAuthState: consumeDecision },
  } as const;
};

export const makePgAuthServices = <
  C extends AnyPgTable,
  R extends AnyPgTable,
  S extends AnyPgTable,
>(
  database: Database,
  mapping: AuthTables<C, R, S>,
) => {
  const auth = makePgAuthStoreServices(database, mapping);
  const oauth = makePgOAuthStateServices(database, mapping);

  return { ...auth, ...oauth, decisions: { ...auth.decisions, ...oauth.decisions } } as const;
};

/**
 * Owns the native outer commit. Keep rejection as a decision value inside the
 * owner; interruption before commit rolls back. Retry an unknown commit outcome
 * only with the same stable request identity.
 */
export function coordinatePgAuthStoreTransaction<
  D extends Database,
  C extends AnyPgTable,
  R extends AnyPgTable,
  A,
  E,
  Requirements,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: AuthStoreTables<C, R>; readonly transaction?: never },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, AuthStoreDecisions> | DatabaseRequirements
>;

export function coordinatePgAuthStoreTransaction<
  D extends Database,
  C extends AnyPgTable,
  R extends AnyPgTable,
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
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, AuthStoreDecisions | TxId> | DatabaseRequirements
>;

export function coordinatePgAuthStoreTransaction<
  D extends Database,
  C extends AnyPgTable,
  R extends AnyPgTable,
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
      const decisions = makePgAuthStoreServices(transaction as never, options.mapping).decisions;
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

export function coordinatePgOAuthStateTransaction<
  D extends Database,
  S extends AnyPgTable,
  A,
  E,
  Requirements,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: OAuthStateTables<S>; readonly transaction?: never },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, OAuthStateDecisions> | DatabaseRequirements
>;

export function coordinatePgOAuthStateTransaction<
  D extends Database,
  S extends AnyPgTable,
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
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, OAuthStateDecisions | TxId> | DatabaseRequirements
>;

export function coordinatePgOAuthStateTransaction<
  D extends Database,
  S extends AnyPgTable,
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
      const decisions = makePgOAuthStateServices(transaction as never, options.mapping).decisions;
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

export function coordinatePgAuthTransaction<
  D extends Database,
  C extends AnyPgTable,
  R extends AnyPgTable,
  S extends AnyPgTable,
  A,
  E,
  Requirements,
  DatabaseError,
  DatabaseRequirements,
>(
  acquire: Effect.Effect<D, DatabaseError, DatabaseRequirements>,
  options: { readonly mapping: AuthTables<C, R, S>; readonly transaction?: never },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, AuthStoreDecisions | OAuthStateDecisions> | DatabaseRequirements
>;

export function coordinatePgAuthTransaction<
  D extends Database,
  C extends AnyPgTable,
  R extends AnyPgTable,
  S extends AnyPgTable,
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
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, AuthStoreDecisions | OAuthStateDecisions | TxId> | DatabaseRequirements
>;

export function coordinatePgAuthTransaction<
  D extends Database,
  C extends AnyPgTable,
  R extends AnyPgTable,
  S extends AnyPgTable,
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
        const decisions = makePgAuthServices(transaction as never, options.mapping).decisions;

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

export const makePgSubjectProvisioningServices = <
  Subject extends AnyPgTable,
  Identifier extends AnyPgTable,
  Request extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: SubjectProvisioningTables<Subject, Identifier, Request, NativeId>,
) => {
  const db = database as RuntimeDatabase;
  const requestTable = mapping.provisioningRequest.table;
  const requestIdColumn = column(requestTable, mapping.provisioningRequest.requestId);
  const requestFingerprintColumn = column(requestTable, mapping.provisioningRequest.fingerprint);
  const requestSubjectColumn = column(requestTable, mapping.provisioningRequest.subjectId);
  const identifierTable = mapping.identifier.table;
  const identifierNamespaceColumn = column(identifierTable, mapping.identifier.namespace);
  const identifierValueColumn = column(identifierTable, mapping.identifier.value);

  const findReceipt = Effect.fn("DrizzlePgIdentity.findReceipt")(function* (requestId: string) {
    const rows = yield* db
      .select({
        fingerprint: requestFingerprintColumn as PgColumn,
        subjectId: requestSubjectColumn as PgColumn,
      })
      .from(requestTable as any)
      .where(eq(requestIdColumn, requestId))
      .limit(1);

    return rows[0];
  });

  const provision = Effect.fn("DrizzlePgIdentity.provision")(function* (
    input: SubjectProvisioningInput,
  ) {
    const fingerprint = provisioningFingerprint(input);
    const existing = yield* findReceipt(input.requestId);

    if (existing !== undefined) {
      if (existing.fingerprint !== fingerprint) return yield* IdentityConflict.make();
      const id = yield* mapping.subjectId.toSubject(existing.subjectId as NativeId);

      return SubjectProvisioned.make({ subjectId: id });
    }

    const attempt = db.transaction((tx) =>
      Effect.gen(function* () {
        const allocated =
          mapping.subject.allocateId === undefined ? undefined : yield* mapping.subject.allocateId;

        const inserted = yield* tx
          .insert(mapping.subject.table as any)
          .values(mapping.subject.encodeInsert(input, allocated) as any)
          .returning({ id: column(mapping.subject.table, mapping.subject.id) as PgColumn });

        const nativeId = (inserted[0]?.id ?? allocated) as NativeId | undefined;

        if (nativeId === undefined) {
          return yield* PersistenceMappingError.make({
            operation: "provisionSubject.generatedId",
            cause: new Error("subject insert did not return its native id"),
          });
        }
        if (input.identifier !== undefined) {
          yield* tx
            .insert(identifierTable as any)
            .values(
              mapping.identifier.encodeInsert(input.identifier, nativeId, input.verifiedAt) as any,
            );
        }
        yield* tx
          .insert(requestTable as any)
          .values(
            mapping.provisioningRequest.encodeInsert(input.requestId, fingerprint, nativeId) as any,
          );

        return nativeId;
      }),
    );

    const nativeId = yield* attempt.pipe(
      Effect.catchCause(
        (
          cause,
        ): Effect.Effect<
          NativeId,
          | Effect.Error<typeof attempt>
          | Effect.Error<ReturnType<typeof findReceipt>>
          | IdentityConflict
        > => {
          if (
            cause.reasons.length === 0 ||
            !cause.reasons.every(
              (reason) =>
                Cause.isFailReason(reason) &&
                isMappedConstraintConflict(mapping.isConstraintConflict, reason.error),
            )
          )
            return Effect.failCause(cause);

          return findReceipt(input.requestId).pipe(
            Effect.flatMap((receipt) => {
              if (receipt !== undefined && receipt.fingerprint === fingerprint) {
                return Effect.succeed(receipt.subjectId as NativeId);
              }
              if (input.identifier === undefined) return IdentityConflict.make();

              return db
                .select({
                  subjectId: column(identifierTable, mapping.identifier.subjectId) as PgColumn,
                })
                .from(identifierTable as any)
                .where(
                  and(
                    eq(identifierNamespaceColumn, input.identifier.namespace),
                    eq(identifierValueColumn, input.identifier.value),
                  ),
                )
                .limit(1)
                .pipe(Effect.flatMap(() => IdentityConflict.make()));
            }),
          );
        },
      ),
    );

    const subjectId = yield* mapping.subjectId.toSubject(nativeId);

    return SubjectProvisioned.make({ subjectId });
  }, mapIdentityFailure);

  return {
    subjectProvisioner: SubjectProvisioner.of({ provision }),
  } as const;
};

export const makePgExternalIdentityServices = <
  Subject extends AnyPgTable,
  External extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: ExternalIdentityTables<Subject, External, NativeId>,
) => {
  const db = database as RuntimeDatabase;
  const externalTable = mapping.externalIdentity.table;

  const externalProviderColumn = column(
    externalTable,
    mapping.externalIdentity.provider,
  ) as PgColumn;

  const externalIssuerColumn = column(externalTable, mapping.externalIdentity.issuer) as PgColumn;
  const externalSubjectColumn = column(externalTable, mapping.externalIdentity.subject) as PgColumn;

  const externalSubjectIdColumn = column(
    externalTable,
    mapping.externalIdentity.subjectId,
  ) as PgColumn;

  const subjectIdColumn = column(mapping.subject.table, mapping.subject.id) as PgColumn;
  const subjectStatusColumn = column(mapping.subject.table, mapping.subject.status) as PgColumn;

  const bind = Effect.fn("DrizzlePgIdentity.bindExternalIdentity")(function* (
    subjectId: SubjectId,
    identity: ExternalIdentity,
  ) {
    const nativeId = yield* mapping.subjectId.toNative(subjectId);

    const decision = yield* db
      .transaction((tx) =>
        Effect.gen(function* () {
          const subjects = yield* tx
            .select({ status: subjectStatusColumn })
            .from(mapping.subject.table as any)
            .where(eq(subjectIdColumn, nativeId))
            .for("update")
            .limit(1);

          if (subjects[0] === undefined || !mapping.subject.isActiveStatus(subjects[0].status))
            return { _tag: "conflict" } as const;

          const links = yield* tx
            .select({ subjectId: externalSubjectIdColumn })
            .from(externalTable as any)
            .where(
              and(
                eq(externalProviderColumn, identity.provider),
                eq(externalIssuerColumn, identity.issuer),
                eq(externalSubjectColumn, identity.subject),
              ),
            )
            .for("update")
            .limit(1);

          if (links[0] !== undefined)
            return mapping.subjectId.equals(links[0].subjectId as NativeId, nativeId)
              ? ({ _tag: "bound" } as const)
              : ({ _tag: "conflict" } as const);
          yield* tx
            .insert(externalTable as any)
            .values(mapping.externalIdentity.encodeInsert(identity, nativeId) as any);

          return { _tag: "bound" } as const;
        }),
      )
      .pipe(
        Effect.catchCause((cause) => {
          if (
            cause.reasons.length === 0 ||
            !cause.reasons.every(
              (reason) =>
                Cause.isFailReason(reason) &&
                isMappedConstraintConflict(mapping.isConstraintConflict, reason.error),
            )
          )
            return Effect.failCause(cause);

          return db
            .select({ subjectId: externalSubjectIdColumn })
            .from(externalTable as any)
            .where(
              and(
                eq(externalProviderColumn, identity.provider),
                eq(externalIssuerColumn, identity.issuer),
                eq(externalSubjectColumn, identity.subject),
              ),
            )
            .limit(1)
            .pipe(
              Effect.map((rows) =>
                rows[0] !== undefined &&
                mapping.subjectId.equals(rows[0].subjectId as NativeId, nativeId)
                  ? ({ _tag: "bound" } as const)
                  : ({ _tag: "conflict" } as const),
              ),
            );
        }),
      );

    if (decision._tag === "conflict") return yield* IdentityConflict.make();
  }, mapIdentityFailure);

  return { externalIdentityMutation: ExternalIdentityMutation.of({ bind }) } as const;
};

export const makePgIdentityServices = <
  Subject extends AnyPgTable,
  Identifier extends AnyPgTable,
  External extends AnyPgTable,
  Request extends AnyPgTable,
  NativeId,
>(
  database: Database,
  mapping: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => ({
  ...makePgSubjectProvisioningServices(database, mapping),
  ...makePgExternalIdentityServices(database, mapping),
});

export const pgLayers = <
  Id,
  C extends AnyPgTable,
  R extends AnyPgTable,
  S extends AnyPgTable,
  Subject extends AnyPgTable,
  Identifier extends AnyPgTable,
  External extends AnyPgTable,
  Request extends AnyPgTable,
  NativeId,
>(
  database: Context.Service<Id, Database>,
  auth: AuthTables<C, R, S>,
  identity: IdentityTables<Subject, Identifier, External, Request, NativeId>,
) => ({
  identity: Layer.merge(
    Layer.effect(
      SubjectProvisioner,
      database.use((db) => Effect.succeed(makePgIdentityServices(db, identity).subjectProvisioner)),
    ),
    Layer.effect(
      ExternalIdentityMutation,
      database.use((db) =>
        Effect.succeed(makePgIdentityServices(db, identity).externalIdentityMutation),
      ),
    ),
  ),
  authStore: Layer.effect(
    AuthStore,
    database.use((db) => Effect.succeed(makePgAuthServices(db, auth).authStore)),
  ),
  oauthStateStore: Layer.effect(
    OAuthStateStore,
    database.use((db) => Effect.succeed(makePgAuthServices(db, auth).oauthStateStore)),
  ),
});
