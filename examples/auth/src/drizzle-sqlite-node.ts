import { requiredAuthConstraints, type AuthTables } from "@yielded/auth-persistence-drizzle";
import type { makeAuthServices } from "@yielded/auth-persistence-drizzle/SqliteNode";
import { OAuthState } from "@yielded/auth/OAuth";
import {
  ConsumeChallenge,
  ConsumeRegistration,
  NewChallenge,
  NewRegistration,
  PendingRegistration,
  TokenDigest,
} from "@yielded/auth/Schema";
import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";
import { DateTime, Duration, Effect, Schema } from "effect";
import type * as CoreSqlClient from "effect/unstable/sql/SqlClient";

export const challenges = sqliteTable(
  "sample_challenges",
  {
    challengeKey: text("challenge_key").primaryKey(),
    digest: text("token_digest").notNull(),
    kind: text("identifier_namespace").notNull(),
    address: text("normalized_value").notNull(),
    use: text("purpose").notNull(),
    otpKey: text("otp_key_id").notNull(),
    otpHash: text("otp_digest").notNull(),
    issuedMillis: integer("issued_millis").notNull(),
    expiresMillis: integer("expires_millis").notNull(),
    maxAttempts: integer("attempt_limit").notNull(),
    failures: integer("failed_attempts").notNull(),
    used: integer("consumed", { mode: "boolean" }).notNull(),
    cooldownMillis: integer("cooldown_millis").notNull(),
  },
  (table) => [
    uniqueIndex("sample_challenge_series").on(table.kind, table.address, table.use),
    uniqueIndex("sample_challenge_digest").on(table.digest),
  ],
);

export const registrations = sqliteTable("sample_registrations", {
  id: text().primaryKey(),
  digest: text().notNull().unique(),
  email: text().notNull(),
  purpose: text().notNull(),
  issuedMillis: integer().notNull(),
  expiresMillis: integer().notNull(),
  used: integer({ mode: "boolean" }).notNull(),
});

export const states = sqliteTable("sample_oauth_states", {
  digest: text().primaryKey(),
  provider: text().notNull(),
  subject: text().notNull(),
  redirect: text().notNull(),
  issuedMillis: integer().notNull(),
  expiresMillis: integer().notNull(),
  used: integer({ mode: "boolean" }).notNull(),
});

export const mapping = {
  constraints: requiredAuthConstraints,
  challenge: {
    table: challenges,
    identifierNamespace: "email",
    encodeInstant: DateTime.toEpochMillis,
    columns: {
      challengeId: "challengeKey",
      tokenDigest: "digest",
      namespace: "kind",
      value: "address",
      purpose: "use",
      otpKeyId: "otpKey",
      otpDigest: "otpHash",
      issuedAt: "issuedMillis",
      expiresAt: "expiresMillis",
      attemptLimit: "maxAttempts",
      failedAttempts: "failures",
      consumed: "used",
    },
    encodeInsert: (input, state) => ({
      challengeKey: input.challengeId,
      digest: input.tokenDigest,
      kind: state.namespace,
      address: input.email,
      use: input.purpose,
      otpKey: input.otpKeyId,
      otpHash: input.otpDigest,
      issuedMillis: DateTime.toEpochMillis(input.issuedAt),
      expiresMillis: DateTime.toEpochMillis(input.expiresAt),
      maxAttempts: input.attemptLimit,
      failures: state.failedAttempts,
      used: state.consumed,
      cooldownMillis: Duration.toMillis(input.resendCooldown),
    }),
    encodeUpdate: (input, state) => ({
      challengeKey: input.challengeId,
      digest: input.tokenDigest,
      kind: state.namespace,
      address: input.email,
      use: input.purpose,
      otpKey: input.otpKeyId,
      otpHash: input.otpDigest,
      issuedMillis: DateTime.toEpochMillis(input.issuedAt),
      expiresMillis: DateTime.toEpochMillis(input.expiresAt),
      maxAttempts: input.attemptLimit,
      failures: state.failedAttempts,
      used: state.consumed,
      cooldownMillis: Duration.toMillis(input.resendCooldown),
    }),
    decode: (row) =>
      Schema.decodeEffect(NewChallenge)({
        challengeId: row.challengeKey,
        tokenDigest: row.digest,
        email: row.address,
        purpose: "sign-in",
        otpDigest: row.otpHash,
        otpKeyId: row.otpKey,
        issuedAt: row.issuedMillis,
        expiresAt: row.expiresMillis,
        attemptLimit: row.maxAttempts,
        resendCooldown: row.cooldownMillis,
      }).pipe(
        Effect.map((challenge) => ({
          challenge,
          namespace: row.kind,
          failedAttempts: row.failures,
          consumed: row.used,
        })),
        Effect.mapError(
          (cause) =>
            ({ _tag: "PersistenceMappingError", operation: "challenge.decode", cause }) as never,
        ),
      ),
  },
  registration: {
    table: registrations,
    columns: {
      registrationId: "id",
      tokenDigest: "digest",
      expiresAt: "expiresMillis",
      consumed: "used",
    },
    encodeInstant: DateTime.toEpochMillis,
    encodeInsert: (input, used) => ({
      id: input.registrationId,
      digest: input.tokenDigest,
      email: input.email,
      purpose: input.purpose,
      issuedMillis: DateTime.toEpochMillis(input.issuedAt),
      expiresMillis: DateTime.toEpochMillis(input.expiresAt),
      used,
    }),
    decode: (row) =>
      Schema.decodeEffect(PendingRegistration)({
        registrationId: row.id,
        email: row.email,
        purpose: "registration",
        issuedAt: row.issuedMillis,
        expiresAt: row.expiresMillis,
      }).pipe(
        Effect.map((registration) => ({ registration, consumed: row.used })),
        Effect.mapError(
          (cause) =>
            ({ _tag: "PersistenceMappingError", operation: "registration.decode", cause }) as never,
        ),
      ),
  },
  oauthState: {
    table: states,
    columns: { stateDigest: "digest", expiresAt: "expiresMillis", consumed: "used" },
    encodeInstant: DateTime.toEpochMillis,
    encodeInsert: (state, used) => ({
      digest: state.stateDigest,
      provider: state.provider,
      subject: state.subjectId,
      redirect: state.redirectUri,
      issuedMillis: DateTime.toEpochMillis(state.issuedAt),
      expiresMillis: DateTime.toEpochMillis(state.expiresAt),
      used,
    }),
    decode: (row) =>
      Schema.decodeEffect(OAuthState)({
        stateDigest: row.digest,
        provider: row.provider,
        subjectId: row.subject,
        redirectUri: row.redirect,
        issuedAt: row.issuedMillis,
        expiresAt: row.expiresMillis,
      }).pipe(
        Effect.map((state) => ({ state, consumed: row.used })),
        Effect.mapError(
          (cause) =>
            ({ _tag: "PersistenceMappingError", operation: "oauth.decode", cause }) as never,
        ),
      ),
  },
} satisfies AuthTables<typeof challenges, typeof registrations, typeof states>;

export const ddl = [
  `create table sample_challenges (challenge_key text primary key, token_digest text not null unique, identifier_namespace text not null, normalized_value text not null, purpose text not null, otp_key_id text not null, otp_digest text not null, issued_millis integer not null, expires_millis integer not null, attempt_limit integer not null, failed_attempts integer not null, consumed integer not null, cooldown_millis integer not null, unique(identifier_namespace, normalized_value, purpose))`,
  `create table sample_registrations (id text primary key, digest text not null unique, email text not null, purpose text not null, issuedMillis integer not null, expiresMillis integer not null, used integer not null)`,
  `create table sample_oauth_states (digest text primary key, provider text not null, subject text not null, redirect text not null, issuedMillis integer not null, expiresMillis integer not null, used integer not null)`,
] as const;

export const verify = (
  label: string,
  sql: CoreSqlClient.SqlClient,
  services: ReturnType<typeof makeAuthServices>,
) =>
  Effect.gen(function* () {
    const ensure = (condition: boolean, message: string) =>
      condition ? Effect.void : Effect.die(message);

    const now = Date.now();

    const newChallenge = (suffix: string, overrides: Record<string, unknown> = {}) =>
      Schema.decodeEffect(NewChallenge)({
        challengeId: `01994d3e-0ab0-7000-8000-${suffix.padStart(12, "0")}`,
        tokenDigest: `sample-token-${suffix}`,
        email: `${suffix}@example.com`,
        purpose: "sign-in",
        otpDigest: `sample-otp-${suffix}`,
        otpKeyId: "key-1",
        issuedAt: now,
        expiresAt: now + 60_000,
        attemptLimit: 3,
        resendCooldown: 1_000,
        ...overrides,
      });

    for (const statement of ddl) yield* sql.unsafe(statement);
    const challenge = yield* newChallenge("1");

    yield* services.authStore.issueChallenge(challenge);

    const attempt = yield* Schema.decodeEffect(ConsumeChallenge)({
      tokenDigest: challenge.tokenDigest,
      otpDigests: { "key-1": challenge.otpDigest },
    });

    const results = yield* Effect.all(
      [services.decisions.consumeChallenge(attempt), services.decisions.consumeChallenge(attempt)],
      { concurrency: "unbounded" },
    );

    yield* ensure(
      results.filter((result) => result._tag === "accepted").length === 1,
      "expected one challenge winner",
    );
    yield* Effect.result(services.authStore.issueChallenge(challenge));
    yield* ensure(
      (yield* services.decisions.consumeChallenge(attempt))._tag === "rejected",
      "consumed challenge replay reopened the proof",
    );

    const budget = yield* newChallenge("2");

    yield* services.authStore.issueChallenge(budget);

    const wrong = yield* Schema.decodeEffect(ConsumeChallenge)({
      tokenDigest: budget.tokenDigest,
      otpDigests: { "key-1": "wrong-digest" },
    });

    yield* Effect.all(
      Array.from({ length: 8 }, () => services.decisions.consumeChallenge(wrong)),
      { concurrency: "unbounded" },
    );

    const budgetRows = yield* sql.unsafe<{ failures: number }>(
      "select failed_attempts as failures from sample_challenges where token_digest = ?",
      [budget.tokenDigest],
    );

    yield* ensure(budgetRows[0]?.failures === 3, "wrong-attempt budget was not persisted");
    yield* ensure(
      (yield* services.decisions.consumeChallenge(
        yield* Schema.decodeEffect(ConsumeChallenge)({
          tokenDigest: budget.tokenDigest,
          otpDigests: { "key-1": budget.otpDigest },
        }),
      ))._tag === "rejected",
      "correct proof passed after attempt exhaustion",
    );

    const cooldown = yield* newChallenge("3", { resendCooldown: 60_000 });

    const cooldownResults = yield* Effect.forEach(
      Array.from({ length: 8 }, (_, index) => index),
      (index) =>
        Schema.decodeEffect(NewChallenge)({
          ...cooldown,
          challengeId: `01994d3e-0ab0-7000-8001-${String(index).padStart(12, "0")}`,
          tokenDigest: `cooldown-${index}`,
          issuedAt: DateTime.toEpochMillis(cooldown.issuedAt),
          expiresAt: DateTime.toEpochMillis(cooldown.expiresAt),
          resendCooldown: Duration.toMillis(cooldown.resendCooldown),
        }).pipe(Effect.flatMap(services.authStore.issueChallenge), Effect.result),
      { concurrency: "unbounded" },
    );

    yield* ensure(
      cooldownResults.filter((result) => result._tag === "Success").length === 1,
      "expected one cooldown issuance winner",
    );

    const registration = yield* Schema.decodeEffect(NewRegistration)({
      registrationId: "01994d3e-0ab0-7000-8002-000000000001",
      tokenDigest: "registration-digest",
      email: "registration@example.com",
      purpose: "registration",
      issuedAt: now,
      expiresAt: now + 60_000,
    });

    yield* services.authStore.issueRegistration(registration);

    const registrationInput = yield* Schema.decodeEffect(ConsumeRegistration)({
      tokenDigest: registration.tokenDigest,
    });

    const registrationResults = yield* Effect.all(
      Array.from({ length: 8 }, () => services.decisions.consumeRegistration(registrationInput)),
      { concurrency: "unbounded" },
    );

    yield* ensure(
      registrationResults.filter((result) => result._tag === "accepted").length === 1,
      "expected one registration winner",
    );

    const state = yield* Schema.decodeEffect(OAuthState)({
      stateDigest: "state-digest",
      provider: "example",
      subjectId: "subject-1",
      redirectUri: "https://example.com/callback",
      issuedAt: now,
      expiresAt: now + 60_000,
    });

    yield* services.oauthStateStore.issue(state);
    const stateDigest = yield* Schema.decodeEffect(TokenDigest)(state.stateDigest);

    const stateResults = yield* Effect.all(
      Array.from({ length: 8 }, () => services.decisions.consumeOAuthState(stateDigest)),
      { concurrency: "unbounded" },
    );

    yield* ensure(
      stateResults.filter((result) => result._tag === "accepted").length === 1,
      "expected one OAuth state winner",
    );
    yield* Effect.log(
      `${label}: challenge, attempt-budget, cooldown, registration and OAuth concurrency verified`,
    );
  });
