import { AuthStore, EmailOtpRejected } from "@yielded/auth/AuthStore";
import { AuthRateLimited, AuthStoreError, InvalidRegistration } from "@yielded/auth/Errors";
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
import type { QueryEffectHKTBase } from "drizzle-orm/effect-core";
import type { SQLiteColumn, AnySQLiteTable } from "drizzle-orm/sqlite-core";
import type { SQLiteEffectDatabase } from "drizzle-orm/sqlite-core/effect/db";
import { Cause, Context, DateTime, Duration, Effect, Schema } from "effect";
import type { SqlError } from "effect/unstable/sql/SqlError";

import {
  column,
  requireStandaloneConsume,
  updateValues,
  type AuthTables,
  type AuthStoreTables,
  type ChallengeConsumeDecision,
  type ConsumeDecision,
  type OAuthStateTables,
} from "./model";
import type { SuppliedService } from "./SuppliedService";

type AnyDatabase = SQLiteEffectDatabase<any, any, AnyRelations>;
type ClosedQueryEffectHKT = QueryEffectHKTBase & { readonly context: never };
type RuntimeDatabase<HKT extends ClosedQueryEffectHKT, RunResult> = SQLiteEffectDatabase<
  HKT,
  RunResult,
  AnyRelations
> &
  Partial<Parameters<typeof requireStandaloneConsume>[0]>;
type TransactionOf<D extends AnyDatabase> = Parameters<Parameters<D["transaction"]>[0]>[0];

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

const selected = <T extends AnySQLiteTable>(row: unknown): InferSelectModel<T> =>
  row as InferSelectModel<T>;

/**
 * Shared SQLite semantics for libSQL, Node, Bun, WASM, Durable Objects and D1.
 * Every mutation here is one conditional statement, so D1 never reaches its
 * unsupported interactive transaction and Durable Objects never suspend in a
 * transactionSync callback.
 */
export const makeSqliteAuthStoreServices = <
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  HKT extends ClosedQueryEffectHKT = ClosedQueryEffectHKT,
  RunResult = unknown,
>(
  database: SQLiteEffectDatabase<HKT, RunResult, AnyRelations>,
  mapping: AuthStoreTables<C, R>,
  standaloneGuard?: Effect.Effect<void, AuthStoreError>,
) => {
  const db = database as RuntimeDatabase<HKT, RunResult>;

  const requireStandalone =
    standaloneGuard ??
    Effect.suspend(() =>
      db.$client === undefined
        ? AuthStoreError.make({ message: "Use a root auth store or its decision transaction API" })
        : requireStandaloneConsume({ $client: db.$client }),
    );

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
  } as Record<string, SQLiteColumn>;

  const registrationTable = mapping.registration.table;
  const registrationColumns = mapping.registration.columns;

  const registration = {
    tokenDigest: column(registrationTable, registrationColumns.tokenDigest),
    expiresAt: column(registrationTable, registrationColumns.expiresAt),
    consumed: column(registrationTable, registrationColumns.consumed),
  } as Record<string, SQLiteColumn>;

  const issueChallenge = Effect.fn("DrizzleSqliteAuthStore.issueChallenge")(function* (
    input: NewChallenge,
  ) {
    const now = yield* DateTime.now;

    const cooldownCutoff = DateTime.mapEpochMillis(
      now,
      (millis) => millis - Duration.toMillis(input.resendCooldown),
    );

    const rows = (yield* Effect.suspend(() => {
      const values = mapping.challenge.encodeInsert(input, {
        namespace: mapping.challenge.identifierNamespace,
        failedAttempts: 0,
        consumed: false,
      });

      const nativeNow = mapping.challenge.encodeInstant(now);
      const nativeCutoff = mapping.challenge.encodeInstant(cooldownCutoff);
      const nativeIssuedAt = mapping.challenge.encodeInstant(input.issuedAt);
      const preservedAttempts = sql`case when ${gt(challenge.expiresAt, nativeNow)} then ${challenge.failedAttempts} else 0 end`;

      const update = mapping.challenge.encodeUpdate(input, {
        namespace: mapping.challenge.identifierNamespace,
        failedAttempts: preservedAttempts as any,
        consumed: false,
      });

      return db
        .insert(challengeTable as any)
        .values(values as any)
        .onConflictDoUpdate({
          target: [challenge.namespace, challenge.value, challenge.purpose],
          set: update as any,
          setWhere: and(
            ne(challenge.challengeId, input.challengeId),
            lt(challenge.issuedAt, nativeIssuedAt),
            or(eq(challenge.consumed, true), lte(challenge.issuedAt, nativeCutoff)),
          ),
        })
        .returning();
    }).pipe(mapStoreWriteFailure)) as ReadonlyArray<unknown>;

    if (rows.length > 0) return;

    const existing = (yield* Effect.suspend(() =>
      db
        .select()
        .from(challengeTable as any)
        .where(
          and(
            eq(challenge.namespace, mapping.challenge.identifierNamespace),
            eq(challenge.value, input.email),
            eq(challenge.purpose, input.purpose),
          ),
        )
        .limit(1),
    ).pipe(mapStoreReadFailure)) as ReadonlyArray<unknown>;

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

  const consumeChallengeDecision = Effect.fn("DrizzleSqliteAuthStore.consumeChallengeDecision")(
    function* (
      input: ConsumeChallenge,
    ): Effect.fn.Return<ChallengeConsumeDecision, AuthStoreError> {
      const now = yield* DateTime.now;

      const alternatives = Object.entries(input.otpDigests).map(([keyId, digest]) =>
        and(eq(challenge.otpKeyId, keyId), eq(challenge.otpDigest, digest)),
      );

      const matches = alternatives.length === 0 ? sql<boolean>`false` : or(...alternatives)!;

      const rows = (yield* Effect.suspend(() =>
        db
          .update(challengeTable as any)
          .set(
            updateValues<C>([
              [
                challengeColumns.consumed,
                sql`case when ${matches} then true else ${challenge.consumed} end`,
              ],
              [
                challengeColumns.failedAttempts,
                sql`${challenge.failedAttempts} + case when ${matches} then 0 else 1 end`,
              ],
            ]) as any,
          )
          .where(
            and(
              eq(challenge.tokenDigest, input.tokenDigest),
              eq(challenge.consumed, false),
              gt(challenge.expiresAt, mapping.challenge.encodeInstant(now)),
              sql`${challenge.failedAttempts} < ${challenge.attemptLimit}`,
            ),
          )
          .returning(),
      ).pipe(mapStoreWriteFailure)) as ReadonlyArray<unknown>;

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

  const consumeChallenge = Effect.fn("DrizzleSqliteAuthStore.consumeChallenge")(function* (
    input: ConsumeChallenge,
  ) {
    yield* requireStandalone;
    const decision = yield* consumeChallengeDecision(input);

    return decision._tag === "accepted"
      ? decision.value
      : yield* EmailOtpRejected.make({ reason: decision.reason });
  });

  const issueRegistration = Effect.fn("DrizzleSqliteAuthStore.issueRegistration")(function* (
    input: NewRegistration,
  ) {
    yield* Effect.suspend(() =>
      db
        .insert(registrationTable as any)
        .values(mapping.registration.encodeInsert(input, false) as any),
    ).pipe(mapStoreWriteFailure);
  });

  const inspectRegistration = Effect.fn("DrizzleSqliteAuthStore.inspectRegistration")(function* (
    tokenDigest: TokenDigest,
  ) {
    const now = yield* DateTime.now;

    const rows = (yield* Effect.suspend(() =>
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
    ).pipe(mapStoreReadFailure)) as ReadonlyArray<unknown>;

    if (rows[0] === undefined) return yield* InvalidRegistration.make();

    const decoded = yield* Effect.suspend(() =>
      mapping.registration.decode(selected<R>(rows[0])),
    ).pipe(mapStoreReadFailure);

    return decoded.registration;
  });

  const consumeRegistrationDecision = Effect.fn(
    "DrizzleSqliteAuthStore.consumeRegistrationDecision",
  )(function* (
    input: ConsumeRegistration,
  ): Effect.fn.Return<ConsumeDecision<void>, AuthStoreError> {
    const now = yield* DateTime.now;

    const rows = (yield* Effect.suspend(() =>
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
        .returning({ consumed: registration.consumed }),
    ).pipe(mapStoreWriteFailure)) as ReadonlyArray<unknown>;

    return rows.length === 0 ? { _tag: "rejected" } : { _tag: "accepted", value: undefined };
  });

  const consumeRegistration = Effect.fn("DrizzleSqliteAuthStore.consumeRegistration")(function* (
    input: ConsumeRegistration,
  ) {
    yield* requireStandalone;
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

export const makeSqliteOAuthStateServices = <
  S extends AnySQLiteTable,
  HKT extends ClosedQueryEffectHKT = ClosedQueryEffectHKT,
  RunResult = unknown,
>(
  database: SQLiteEffectDatabase<HKT, RunResult, AnyRelations>,
  mapping: OAuthStateTables<S>,
  standaloneGuard?: Effect.Effect<void, AuthStoreError>,
) => {
  const db = database as RuntimeDatabase<HKT, RunResult>;

  const requireStandalone =
    standaloneGuard ??
    Effect.suspend(() =>
      db.$client === undefined
        ? AuthStoreError.make({ message: "Use a root auth store or its decision transaction API" })
        : requireStandaloneConsume({ $client: db.$client }),
    );

  const stateTable = mapping.oauthState.table;
  const stateColumns = mapping.oauthState.columns;

  const state = {
    stateDigest: column(stateTable, stateColumns.stateDigest),
    expiresAt: column(stateTable, stateColumns.expiresAt),
    consumed: column(stateTable, stateColumns.consumed),
  } as Record<string, SQLiteColumn>;

  const issue = Effect.fn("DrizzleSqliteOAuthStateStore.issue")(function* (input: OAuthState) {
    yield* Effect.suspend(() =>
      db.insert(stateTable as any).values(mapping.oauthState.encodeInsert(input, false) as any),
    ).pipe(mapStoreWriteFailure);
  });

  const consumeDecision = Effect.fn("DrizzleSqliteOAuthStateStore.consumeDecision")(function* (
    digest: TokenDigest,
  ): Effect.fn.Return<ConsumeDecision<OAuthState>, AuthStoreError> {
    const now = yield* DateTime.now;

    const rows = (yield* Effect.suspend(() =>
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
    ).pipe(mapStoreWriteFailure)) as ReadonlyArray<unknown>;

    if (rows[0] === undefined) return { _tag: "rejected" };

    const decoded = yield* Effect.suspend(() =>
      mapping.oauthState.decode(selected<S>(rows[0])),
    ).pipe(mapStoreReadFailure);

    return { _tag: "accepted", value: decoded.state };
  });

  const consume = Effect.fn("DrizzleSqliteOAuthStateStore.consume")(function* (
    digest: TokenDigest,
  ) {
    yield* requireStandalone;
    const decision = yield* consumeDecision(digest);

    return decision._tag === "accepted" ? decision.value : yield* InvalidOAuthState.make();
  });

  return {
    oauthStateStore: OAuthStateStore.of({ issue, consume }),
    decisions: { consumeOAuthState: consumeDecision },
  } as const;
};

export const makeSqliteAuthServices = <
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
  HKT extends ClosedQueryEffectHKT = ClosedQueryEffectHKT,
  RunResult = unknown,
>(
  database: SQLiteEffectDatabase<HKT, RunResult, AnyRelations>,
  mapping: AuthTables<C, R, S>,
  standaloneGuard?: Effect.Effect<void, AuthStoreError>,
) => {
  const auth = makeSqliteAuthStoreServices(database, mapping, standaloneGuard);
  const oauth = makeSqliteOAuthStateServices(database, mapping, standaloneGuard);

  return { ...auth, ...oauth, decisions: { ...auth.decisions, ...oauth.decisions } } as const;
};

/**
 * Owns the native outer commit for interactive SQLite targets. Keep rejection
 * as a decision value inside the owner; interruption before commit rolls back.
 */
export function coordinateSqliteAuthStoreTransaction<
  D extends AnyDatabase,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
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

export function coordinateSqliteAuthStoreTransaction<
  D extends AnyDatabase,
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
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, AuthStoreDecisions | TxId> | DatabaseRequirements
>;

export function coordinateSqliteAuthStoreTransaction<
  D extends AnyDatabase,
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

export function coordinateSqliteOAuthStateTransaction<
  D extends AnyDatabase,
  S extends AnySQLiteTable,
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

export function coordinateSqliteOAuthStateTransaction<
  D extends AnyDatabase,
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
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, OAuthStateDecisions | TxId> | DatabaseRequirements
>;

export function coordinateSqliteOAuthStateTransaction<
  D extends AnyDatabase,
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

export function coordinateSqliteAuthTransaction<
  D extends AnyDatabase,
  C extends AnySQLiteTable,
  R extends AnySQLiteTable,
  S extends AnySQLiteTable,
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

export function coordinateSqliteAuthTransaction<
  D extends AnyDatabase,
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
    readonly transaction: SuppliedService<TxId, NoInfer<TransactionOf<D>>, TxShape>;
  },
  body: Effect.Effect<A, E, Requirements>,
): Effect.Effect<
  A,
  E | DatabaseError | SqlError,
  Exclude<Requirements, AuthStoreDecisions | OAuthStateDecisions | TxId> | DatabaseRequirements
>;

export function coordinateSqliteAuthTransaction<
  D extends AnyDatabase,
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
