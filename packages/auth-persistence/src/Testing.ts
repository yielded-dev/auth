/** Explicit Node.js test support. Never imported by production entrypoints. */
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { PasswordHashing, PasswordPersistence, PasswordUnavailable } from "@yielded/auth/Password";
import { hooksLayer } from "@yielded/auth/Persistence";
import { Email, SubjectId } from "@yielded/auth/Schema";
import { AuthenticationAuthority, AuthenticationRequirement } from "@yielded/auth/Sessions";
import { Clock, Context, type Crypto, Effect, Layer, Redacted, Schema } from "effect";
import { SqlClient } from "effect/sql";

import {
  PersistenceConfigurationError,
  type ClaimsCodec,
  type Definition,
} from "./internal/configuration";
import type { PersistenceMappingError } from "./internal/mapping-error";
import { makeNativeSqlTables } from "./internal/native-sql-table";
import { makeNativePasswordServices } from "./internal/password-native";
import { makeNativeAuthenticationAuthorityServices } from "./internal/session-native-authority";
import { makeNativeStatefulSessionServices } from "./internal/session-native-stateful";
import { SqlBatchCommit } from "./internal/sql-commit";
import { AuthPersistence } from "./internal/sql-persistence";
import { identifier, type Table } from "./internal/sql-table";
import { makeMappings } from "./internal/storage-mapping";
import { tableDefinition } from "./internal/storage-tables";

/** One existing subject and one byte-preserving password. Seeding does not verify
 * an email or exercise registration/screening. Passwords are hashed on acquisition
 * by the supplied PasswordHashing service; they are never stored as plaintext. */
export const PasswordSubject = Schema.Struct({
  subjectId: SubjectId,
  email: Email,
  password: Schema.Redacted(Schema.String),
  active: Schema.optionalKey(Schema.Boolean),
});

export interface Options {
  readonly subjects: ReadonlyArray<typeof PasswordSubject.Encoded>;
  /** Application policy; no permissive test default. */
  readonly requirement: AuthenticationRequirement;
  /** Use a manually synchronized SQL clock with Effect's test clock. Omit for
   * SQLite engine time. Call syncClock after changing the Effect clock, between
   * operations; this does not simulate independent-clock races. */
  readonly clock?: "test";
}

class DatabaseClock extends Context.Service<
  DatabaseClock,
  {
    readonly sync: Effect.Effect<void, PersistenceConfigurationError>;
  }
>()("@yielded/auth-persistence/Testing/DatabaseClock") {}

/** Copy the acquired Effect Clock's current time into this test database.
 * Requires clock: "test". Does not advance Effect's clock or synchronize fibers. */
export const syncClock = Effect.flatMap(DatabaseClock, (clock) => clock.sync);

const configurationError = (reason: string) => PersistenceConfigurationError.make({ reason });

const createTable = Effect.fnUntraced(function* (table: Table) {
  const sql = yield* SqlClient.SqlClient;

  const columns = Object.values(table.columns).map(
    ({ options }) =>
      `${identifier(options.name)} ${options.type === "text" ? "text" : "integer"}${options.nullable ? "" : " not null"}`,
  );

  const unique = table.unique.map(
    (keys) =>
      `unique (${keys.map((key) => identifier(table.columns[key].options.name)).join(", ")})`,
  );

  yield* sql.unsafe(
    `create table ${identifier(table.name)} (${[...columns, ...unique].join(", ")})`,
  );
});

/** Fresh scoped SQLite :memory: storage for exactly one Password.make() sign-in
 * strategy and stateful sessions: issue, verify, renew, list, revoke and sign out.
 * The real SQL authority and session factories retain their transaction checks.
 * Other strategies, password management and session modes fail at acquisition.
 * Claims, hashing, Crypto, session policy and private delivery remain application
 * responsibilities. No SQL client, registration, MFA or identity-mutation port is
 * exposed. Reusing this Layer within one build shares state; separate acquisitions
 * own separate databases, discarded on scope close. Requires node:sqlite through
 * the optional @effect/sql-sqlite-node peer. Never use for production authority.
 */
export const layer = <C extends ClaimsCodec, const Id extends string>(
  auth: Definition<C, Id>,
  options: Options,
): Layer.Layer<
  | AuthenticationAuthority
  | PasswordPersistence
  | DatabaseClock
  | Context.Service.Identifier<Definition<C, Id>["sessions"]["StatefulSessionPersistence"]>
  | Context.Service.Identifier<Definition<C, Id>["sessions"]["SessionRepository"]>,
  PersistenceConfigurationError | PersistenceMappingError | PasswordUnavailable,
  Crypto.Crypto | PasswordHashing
> =>
  Layer.unwrap(
    Effect.gen(function* () {
      const strategies = Object.values(auth.strategies);
      const feature = strategies[0]?.persistence;

      if (
        auth.sessionMode !== "stateful" ||
        strategies.length !== 1 ||
        feature?.kind !== "password" ||
        feature.management ||
        feature.lifecycle
      ) {
        return yield* configurationError(
          "Testing.layer supports one sign-in-only Password.make() strategy and stateful sessions",
        );
      }

      const seeds = yield* Schema.decodeEffect(Schema.Array(PasswordSubject))(
        options.subjects,
      ).pipe(Effect.mapError(() => configurationError("Invalid in-memory password subjects")));

      const requirement = yield* Schema.decodeEffect(AuthenticationRequirement)(
        options.requirement,
      ).pipe(
        Effect.mapError(() => configurationError("Invalid in-memory authentication requirement")),
      );

      const subjects = AuthPersistence.table(tableDefinition("subjects", "test_subjects"));

      const storage = AuthPersistence.make(auth).managed({
        prefix: "test_auth",
        subjects: {
          table: subjects,
          id: "id",
          status: "active",
          activeValue: true,
          securityRevision: "securityRevision",
          idCodec: SubjectId,
          requirements: () => Effect.succeed(requirement),
        },
      });

      return Layer.effectContext(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient;
          const hasher = yield* PasswordHashing;
          const clock = yield* Clock.Clock;
          const tables = makeNativeSqlTables(sql);

          const sync =
            options.clock === "test"
              ? Effect.gen(function* () {
                  const millis = yield* Schema.decodeEffect(Schema.Int)(
                    clock.currentTimeMillisUnsafe(),
                  );

                  yield* sql`update test_clock set millis = ${millis}`;
                }).pipe(
                  Effect.mapError(() =>
                    configurationError("Cannot synchronize the in-memory SQL clock"),
                  ),
                )
              : Effect.fail(configurationError("syncClock requires clock: test"));

          yield* sql
            .withTransaction(
              Effect.gen(function* () {
                for (const table of [subjects, ...Object.values(storage.schema)])
                  yield* createTable(table);
                if (options.clock === "test") {
                  yield* sql`create table test_clock (millis integer not null)`;
                  yield* sql`insert into test_clock values (0)`;
                  yield* sync;
                }
                for (const seed of seeds) {
                  const verifier = yield* hasher.hash(seed.password);
                  const credentialId = `password:${seed.subjectId}`;

                  yield* sql`${tables(subjects).insert({ id: seed.subjectId, active: seed.active ?? true, securityRevision: "1" })}`;
                  yield* sql`${tables(storage.schema.identifiers).insert({
                    namespace: "email",
                    value: seed.email,
                    subjectId: seed.subjectId,
                    revision: "1",
                    verifiedAt: null,
                    active: true,
                  })}`;
                  yield* sql`${tables(storage.schema.credentials).insert({
                    credentialId,
                    subjectId: seed.subjectId,
                    revision: "1",
                    active: true,
                  })}`;
                  const passwords = storage.tables.passwords;

                  if (passwords === undefined)
                    return yield* configurationError("Missing in-memory password storage");
                  yield* sql`${tables(passwords).insert({
                    moduleId: feature.moduleId,
                    subjectId: seed.subjectId,
                    credentialId,
                    credentialRevision: "1",
                    verifierVersion: "1",
                    verifier: Redacted.value(verifier),
                    normalization: "none",
                  })}`;
                }
              }),
            )
            .pipe(
              Effect.mapError(() =>
                configurationError(
                  "Cannot seed in-memory password storage; check subjects, duplicate IDs/emails and hashing",
                ),
              ),
            );

          const mappings = yield* makeMappings(storage);
          const passwordMapping = mappings.passwords();
          const sessionMapping = mappings.sessions(auth.claims, auth.sessions.moduleId);

          const storageClock =
            options.clock === "test"
              ? { ...sessionMapping.clock, engineNowMillis: sql`(select millis from test_clock)` }
              : sessionMapping.clock;

          const sessions = { ...sessionMapping, clock: storageClock };

          const { authenticationAuthority } = yield* makeNativeAuthenticationAuthorityServices(
            tables,
            sessions,
          );

          const { statefulSessionPersistence, sessionRepository } =
            yield* makeNativeStatefulSessionServices(tables, sessions);

          const { passwordPersistence } = yield* makeNativePasswordServices(tables, {
            ...passwordMapping,
            clock: storageClock,
          });

          const unsupported = () => Effect.fail(PasswordUnavailable.make({}));

          return Context.make(AuthenticationAuthority, authenticationAuthority).pipe(
            Context.add(auth.sessions.StatefulSessionPersistence, statefulSessionPersistence),
            Context.add(auth.sessions.SessionRepository, sessionRepository),
            Context.add(PasswordPersistence, {
              ...passwordPersistence,
              readForSubject: unsupported,
              recoveryTarget: unsupported,
              addIfAbsent: unsupported,
              replaceIfCurrent: unsupported,
              resetWithProof: unsupported,
            }),
            Context.add(DatabaseClock, { sync }),
          );
        }),
      ).pipe(
        Layer.provide(hooksLayer),
        Layer.provide(Layer.succeed(SqlBatchCommit, undefined)),
        Layer.provide(SqliteClient.layer({ filename: ":memory:" })),
      );
    }),
  );
