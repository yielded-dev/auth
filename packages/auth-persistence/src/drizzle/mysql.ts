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
  timingSafeStringEqual,
  VerifiedEmail,
  type ConsumeChallenge,
  type ConsumeRegistration,
  type NewChallenge,
  type NewRegistration,
  type TokenDigest,
} from "@yielded/auth/Schema";
/* oxlint-disable no-explicit-any -- Drizzle's generic query builders lose the concrete consumer table through a runtime column map. Assertions stay in this adapter. */
import { and, eq, gt, sql, type AnyRelations, type InferSelectModel } from "drizzle-orm";
import type { EffectMysql2Database } from "drizzle-orm/effect-mysql2";
import type { AnyMySqlTable, MySqlColumn } from "drizzle-orm/mysql-core";
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

type Database = EffectMysql2Database<AnyRelations>;
type RuntimeDatabase = EffectMysql2Database<any> & Parameters<typeof requireStandaloneConsume>[0];
type TransactionOf<D extends Database> = Parameters<Parameters<D["transaction"]>[0]>[0];

const selected = <T extends AnyMySqlTable>(row: unknown): InferSelectModel<T> =>
  row as InferSelectModel<T>;

const readError = () => AuthStoreError.make({ message: "Auth store read failed" });
const writeError = () => AuthStoreError.make({ message: "Auth store write failed" });
const isStoreFailure = Schema.is(AuthStoreError);

const mapStoreFailure =
  (failure: () => AuthStoreError) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, AuthStoreError, R> =>
    reportPersistenceFailure(effect, isStoreFailure).pipe(
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, failure))),
    );

const mapStoreReadFailure = mapStoreFailure(readError);
const mapStoreWriteFailure = mapStoreFailure(writeError);

/** MySQL/InnoDB implementation. Multi-step decisions stay values until commit. */
export const makeMysqlAuthStoreServices = <C extends AnyMySqlTable, R extends AnyMySqlTable>(
  database: Database,
  mapping: AuthStoreTables<C, R>,
) => {
  const db = database as RuntimeDatabase;
  const challengeTable = mapping.challenge.table;
  const ck = mapping.challenge.columns;

  const c = Object.fromEntries(
    Object.entries(ck).map(([name, key]) => [name, column(challengeTable, key)]),
  ) as Record<keyof typeof ck, MySqlColumn>;

  const registrationTable = mapping.registration.table;
  const rk = mapping.registration.columns;

  const r = Object.fromEntries(
    Object.entries(rk).map(([name, key]) => [name, column(registrationTable, key)]),
  ) as Record<keyof typeof rk, MySqlColumn>;

  const issueChallenge = Effect.fn("DrizzleMysqlAuthStore.issueChallenge")(function* (
    input: NewChallenge,
  ) {
    const result = yield* Effect.suspend(() =>
      db.transaction((tx) =>
        Effect.gen(function* () {
          // A locking read of a missing InnoDB key takes a gap lock. Concurrent
          // first issuances would then deadlock when each transaction inserts.
          // The no-op upsert serializes on the declared series/digest unique
          // indexes before the row is read and evaluated below.
          yield* tx
            .insert(challengeTable as any)
            .values(
              mapping.challenge.encodeInsert(input, {
                namespace: mapping.challenge.identifierNamespace,
                failedAttempts: 0,
                consumed: false,
              }) as any,
            )
            .onDuplicateKeyUpdate({
              set: updateValues<C>([[ck.challengeId, c.challengeId]]) as any,
            });

          const rows = yield* tx
            .select()
            .from(challengeTable as any)
            .where(
              and(
                eq(c.namespace, mapping.challenge.identifierNamespace),
                eq(c.value, input.email),
                eq(c.purpose, input.purpose),
              ),
            )
            .for("update")
            .limit(1);

          // A digest collision against another series is not a replay and must
          // never overwrite that row.
          if (rows[0] === undefined)
            return yield* AuthStoreError.make({ message: "Challenge digest conflict" });
          const existing = yield* mapping.challenge.decode(selected<C>(rows[0]));
          const now = yield* DateTime.now;

          const exactReplay =
            existing.challenge.challengeId === input.challengeId &&
            timingSafeStringEqual(existing.challenge.tokenDigest, input.tokenDigest) &&
            existing.challenge.email === input.email &&
            existing.challenge.purpose === input.purpose &&
            existing.challenge.otpKeyId === input.otpKeyId &&
            timingSafeStringEqual(existing.challenge.otpDigest, input.otpDigest) &&
            DateTime.toEpochMillis(existing.challenge.issuedAt) ===
              DateTime.toEpochMillis(input.issuedAt) &&
            DateTime.toEpochMillis(existing.challenge.expiresAt) ===
              DateTime.toEpochMillis(input.expiresAt) &&
            existing.challenge.attemptLimit === input.attemptLimit &&
            Duration.toMillis(existing.challenge.resendCooldown) ===
              Duration.toMillis(input.resendCooldown);

          // Retrying an identical still-live request is idempotent. In
          // particular, it does not reset the persisted wrong-attempt budget.
          if (
            exactReplay &&
            !existing.consumed &&
            DateTime.toEpochMillis(existing.challenge.expiresAt) > DateTime.toEpochMillis(now)
          )
            return { _tag: "issued" } as const;
          if (exactReplay) return { _tag: "limited", retryAfterSeconds: 1 } as const;
          if (
            existing.challenge.challengeId === input.challengeId ||
            DateTime.toEpochMillis(input.issuedAt) <=
              DateTime.toEpochMillis(existing.challenge.issuedAt)
          )
            return { _tag: "limited", retryAfterSeconds: 1 } as const;

          const eligibleAt =
            DateTime.toEpochMillis(existing.challenge.issuedAt) +
            Duration.toMillis(input.resendCooldown);

          if (!existing.consumed && DateTime.toEpochMillis(now) < eligibleAt) {
            return {
              _tag: "limited",
              retryAfterSeconds: Math.max(
                1,
                Math.ceil((eligibleAt - DateTime.toEpochMillis(now)) / 1000),
              ),
            } as const;
          }

          const failedAttempts =
            DateTime.toEpochMillis(existing.challenge.expiresAt) > DateTime.toEpochMillis(now)
              ? existing.failedAttempts
              : 0;

          yield* tx
            .update(challengeTable as any)
            .set(
              mapping.challenge.encodeUpdate(input, {
                namespace: mapping.challenge.identifierNamespace,
                failedAttempts,
                consumed: false,
              }) as any,
            )
            .where(
              and(
                eq(c.namespace, mapping.challenge.identifierNamespace),
                eq(c.value, input.email),
                eq(c.purpose, input.purpose),
              ),
            );

          return { _tag: "issued" } as const;
        }),
      ),
    ).pipe(mapStoreWriteFailure);

    if (result._tag === "limited")
      return yield* AuthRateLimited.make({ retryAfterSeconds: result.retryAfterSeconds });
  });

  const consumeChallengeDecision = Effect.fn("DrizzleMysqlAuthStore.consumeChallengeDecision")(
    function* (
      input: ConsumeChallenge,
    ): Effect.fn.Return<ChallengeConsumeDecision, AuthStoreError> {
      return yield* Effect.suspend(() =>
        db.transaction((tx) =>
          Effect.gen(function* () {
            const rows = yield* tx
              .select()
              .from(challengeTable as any)
              .where(eq(c.tokenDigest, input.tokenDigest))
              .for("update")
              .limit(1);

            if (rows[0] === undefined)
              return { _tag: "rejected", reason: "missing_challenge" } as const;
            const row = yield* mapping.challenge.decode(selected<C>(rows[0]));
            const now = yield* DateTime.now;

            if (row.consumed) return { _tag: "rejected", reason: "consumed_challenge" } as const;
            if (DateTime.toEpochMillis(row.challenge.expiresAt) <= DateTime.toEpochMillis(now))
              return { _tag: "rejected", reason: "expired_challenge" } as const;
            if (row.failedAttempts >= row.challenge.attemptLimit)
              return { _tag: "rejected", reason: "attempts_exhausted" } as const;
            const candidate = input.otpDigests[row.challenge.otpKeyId];

            const matches =
              candidate !== undefined && timingSafeStringEqual(candidate, row.challenge.otpDigest);

            yield* tx
              .update(challengeTable as any)
              .set(
                updateValues<C>(
                  matches
                    ? [[ck.consumed, true]]
                    : [[ck.failedAttempts, sql`${c.failedAttempts} + 1`]],
                ) as any,
              )
              .where(eq(c.tokenDigest, input.tokenDigest));

            return matches
              ? ({
                  _tag: "accepted",
                  value: VerifiedEmail.make({
                    email: row.challenge.email,
                    purpose: row.challenge.purpose,
                  }),
                } as const)
              : ({ _tag: "rejected", reason: "bad_code" } as const);
          }),
        ),
      ).pipe(mapStoreWriteFailure);
    },
  );

  const consumeChallenge = Effect.fn("DrizzleMysqlAuthStore.consumeChallenge")(function* (
    input: ConsumeChallenge,
  ) {
    yield* requireStandaloneConsume(db);
    const decision = yield* consumeChallengeDecision(input);

    return decision._tag === "accepted"
      ? decision.value
      : yield* EmailOtpRejected.make({ reason: decision.reason });
  });

  const issueRegistration = Effect.fn("DrizzleMysqlAuthStore.issueRegistration")(function* (
    input: NewRegistration,
  ) {
    yield* Effect.suspend(() =>
      db
        .insert(registrationTable as any)
        .values(mapping.registration.encodeInsert(input, false) as any),
    ).pipe(mapStoreWriteFailure);
  });

  const inspectRegistration = Effect.fn("DrizzleMysqlAuthStore.inspectRegistration")(function* (
    digest: TokenDigest,
  ) {
    const now = yield* DateTime.now;

    const rows = yield* Effect.suspend(() =>
      db
        .select()
        .from(registrationTable as any)
        .where(
          and(
            eq(r.tokenDigest, digest),
            eq(r.consumed, false),
            gt(r.expiresAt, mapping.registration.encodeInstant(now)),
          ),
        )
        .limit(1),
    ).pipe(mapStoreReadFailure);

    if (rows[0] === undefined) return yield* InvalidRegistration.make();

    return (yield* Effect.suspend(() => mapping.registration.decode(selected<R>(rows[0]))).pipe(
      mapStoreReadFailure,
    )).registration;
  });

  const consumeRegistrationDecision = Effect.fn(
    "DrizzleMysqlAuthStore.consumeRegistrationDecision",
  )(function* (
    input: ConsumeRegistration,
  ): Effect.fn.Return<ConsumeDecision<void>, AuthStoreError> {
    return yield* Effect.suspend(() =>
      db.transaction((tx) =>
        Effect.gen(function* () {
          const rows = yield* tx
            .select()
            .from(registrationTable as any)
            .where(eq(r.tokenDigest, input.tokenDigest))
            .for("update")
            .limit(1);

          if (rows[0] === undefined) return { _tag: "rejected" } as const;
          const row = yield* mapping.registration.decode(selected<R>(rows[0]));
          const now = yield* DateTime.now;

          if (
            row.consumed ||
            DateTime.toEpochMillis(row.registration.expiresAt) <= DateTime.toEpochMillis(now)
          )
            return { _tag: "rejected" } as const;
          yield* tx
            .update(registrationTable as any)
            .set(updateValues<R>([[rk.consumed, true]]) as any)
            .where(eq(r.tokenDigest, input.tokenDigest));

          return { _tag: "accepted", value: undefined } as const;
        }),
      ),
    ).pipe(mapStoreWriteFailure);
  });

  const consumeRegistration = Effect.fn("DrizzleMysqlAuthStore.consumeRegistration")(function* (
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

export const makeMysqlOAuthStateServices = <S extends AnyMySqlTable>(
  database: Database,
  mapping: OAuthStateTables<S>,
) => {
  const db = database as RuntimeDatabase;
  const stateTable = mapping.oauthState.table;
  const sk = mapping.oauthState.columns;

  const s = Object.fromEntries(
    Object.entries(sk).map(([name, key]) => [name, column(stateTable, key)]),
  ) as Record<keyof typeof sk, MySqlColumn>;

  const issue = Effect.fn("DrizzleMysqlOAuthStateStore.issue")(function* (input: OAuthState) {
    yield* Effect.suspend(() =>
      db.insert(stateTable as any).values(mapping.oauthState.encodeInsert(input, false) as any),
    ).pipe(mapStoreWriteFailure);
  });

  const consumeDecision = Effect.fn("DrizzleMysqlOAuthStateStore.consumeDecision")(function* (
    digest: TokenDigest,
  ): Effect.fn.Return<ConsumeDecision<OAuthState>, AuthStoreError> {
    return yield* Effect.suspend(() =>
      db.transaction((tx) =>
        Effect.gen(function* () {
          const rows = yield* tx
            .select()
            .from(stateTable as any)
            .where(eq(s.stateDigest, digest))
            .for("update")
            .limit(1);

          if (rows[0] === undefined) return { _tag: "rejected" } as const;
          const row = yield* mapping.oauthState.decode(selected<S>(rows[0]));
          const now = yield* DateTime.now;

          if (
            row.consumed ||
            DateTime.toEpochMillis(row.state.expiresAt) <= DateTime.toEpochMillis(now)
          )
            return { _tag: "rejected" } as const;
          yield* tx
            .update(stateTable as any)
            .set(updateValues<S>([[sk.consumed, true]]) as any)
            .where(eq(s.stateDigest, digest));

          return { _tag: "accepted", value: row.state } as const;
        }),
      ),
    ).pipe(mapStoreWriteFailure);
  });

  const consume = Effect.fn("DrizzleMysqlOAuthStateStore.consume")(function* (digest: TokenDigest) {
    yield* requireStandaloneConsume(db);
    const decision = yield* consumeDecision(digest);

    return decision._tag === "accepted" ? decision.value : yield* InvalidOAuthState.make();
  });

  return {
    oauthStateStore: OAuthStateStore.of({ issue, consume }),
    decisions: { consumeOAuthState: consumeDecision },
  } as const;
};

export const makeMysqlAuthServices = <
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
  S extends AnyMySqlTable,
>(
  database: Database,
  mapping: AuthTables<C, R, S>,
) => {
  const auth = makeMysqlAuthStoreServices(database, mapping);
  const oauth = makeMysqlOAuthStateServices(database, mapping);

  return { ...auth, ...oauth, decisions: { ...auth.decisions, ...oauth.decisions } } as const;
};

/**
 * Owns the native outer commit. Keep rejection as a decision value inside the
 * owner; interruption before commit rolls back. This adapter never retries a
 * deadlock inside the caller's transaction.
 */
export function coordinateMysqlAuthStoreTransaction<
  D extends Database,
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
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

export function coordinateMysqlAuthStoreTransaction<
  D extends Database,
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
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

export function coordinateMysqlAuthStoreTransaction<
  D extends Database,
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
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
      const decisions = makeMysqlAuthStoreServices(transaction as never, options.mapping).decisions;
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

export function coordinateMysqlOAuthStateTransaction<
  D extends Database,
  S extends AnyMySqlTable,
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

export function coordinateMysqlOAuthStateTransaction<
  D extends Database,
  S extends AnyMySqlTable,
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

export function coordinateMysqlOAuthStateTransaction<
  D extends Database,
  S extends AnyMySqlTable,
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
      const decisions = makeMysqlOAuthStateServices(
        transaction as never,
        options.mapping,
      ).decisions;

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

export function coordinateMysqlAuthTransaction<
  D extends Database,
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
  S extends AnyMySqlTable,
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

export function coordinateMysqlAuthTransaction<
  D extends Database,
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
  S extends AnyMySqlTable,
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

export function coordinateMysqlAuthTransaction<
  D extends Database,
  C extends AnyMySqlTable,
  R extends AnyMySqlTable,
  S extends AnyMySqlTable,
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
        const decisions = makeMysqlAuthServices(transaction as never, options.mapping).decisions;

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
