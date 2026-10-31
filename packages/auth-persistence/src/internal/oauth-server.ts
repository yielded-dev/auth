import { AssertionReceipt, Persistence, Record, Unavailable } from "@yielded/auth/OAuthServer";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";
import * as SqlError from "effect/sql/SqlError";
import type * as Statement from "effect/sql/Statement";

import { executeSqlChange } from "./sql-change";
import { requireStandalone } from "./standalone";

const codec = Schema.fromJsonString(Record);

const Row = Schema.Struct({
  payload: Schema.String,
  version: Schema.String,
  revoked: Schema.Literals([0, 1]),
});

/** Apply once through application migrations. `migrations` serve SQLite (including
 * D1) and PostgreSQL; `mysqlMigrations` serve MySQL and MariaDB.
 * Expired records may be deleted when expires_at_millis <= the current time.
 * Revocation has its own monotonic column so it cannot lose a race with rotation.
 */
const migrations = [
  `CREATE TABLE yielded_oauth_server (
  namespace TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  version TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  expires_at_millis BIGINT NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY (namespace, grant_id)
)`,
  `CREATE TABLE yielded_oauth_client_assertion (
  namespace TEXT NOT NULL,
  assertion_id TEXT NOT NULL,
  expires_at_millis BIGINT NOT NULL,
  PRIMARY KEY (namespace, assertion_id)
)`,
];

const mysqlNamespaceLength = 512;
const mysqlKeyLength = 64;

/** Keys are binary-collated so that a token never matches a case variant of itself. */
const mysqlMigrations = [
  `CREATE TABLE yielded_oauth_server (
  namespace VARCHAR(${mysqlNamespaceLength}) NOT NULL,
  grant_id VARCHAR(${mysqlKeyLength}) NOT NULL,
  version VARCHAR(${mysqlKeyLength}) NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  expires_at_millis BIGINT NOT NULL,
  payload LONGTEXT NOT NULL,
  PRIMARY KEY (namespace, grant_id)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`,
  `CREATE TABLE yielded_oauth_client_assertion (
  namespace VARCHAR(${mysqlNamespaceLength}) NOT NULL,
  assertion_id VARCHAR(${mysqlKeyLength}) NOT NULL,
  expires_at_millis BIGINT NOT NULL,
  PRIMARY KEY (namespace, assertion_id)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`,
];

const layer = Layer.effect(
  Persistence,
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    if (
      !sql.onDialectOrElse({
        sqlite: () => true,
        pg: () => true,
        mysql: () => true,
        orElse: () => false,
      })
    )
      return yield* Unavailable.make({});
    const standalone = requireStandalone(() => Unavailable.make({}), sql.transactionService);

    const failure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
      reportPersistenceFailure(effect, Schema.is(Unavailable), { markReported: true }).pipe(
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => Unavailable.make({}))),
        ),
      );

    /** Outside strict mode MySQL stores an overlong key cut, so refuse it first. */
    const requireFit = (namespace: string, id: string) =>
      sql.onDialectOrElse({
        mysql: () =>
          namespace.length > mysqlNamespaceLength || id.length > mysqlKeyLength
            ? Effect.fail(Unavailable.make({}))
            : Effect.void,
        orElse: () => Effect.void,
      });

    /** MySQL has neither ON CONFLICT nor RETURNING, so its primary key decides. */
    const claim = (insert: Statement.Fragment, conflict: Statement.Fragment) =>
      sql.onDialectOrElse({
        mysql: () =>
          sql`${insert}`.pipe(
            Effect.as(true),
            Effect.catchIf(
              (error) =>
                Schema.is(SqlError.SqlError)(error) && error.reason._tag === "UniqueViolation",
              () => Effect.succeed(false),
            ),
          ),
        orElse: () => sql`${insert} ${conflict}`.pipe(Effect.map((rows) => rows.length === 1)),
      });

    return Persistence.of({
      consumeAssertion: Effect.fn("OAuthServerPersistence.consumeAssertion")(function* (
        namespace,
        input,
      ) {
        yield* standalone;
        const receipt = yield* Schema.decodeEffect(AssertionReceipt)(input);

        yield* requireFit(namespace, receipt.id);

        return yield* claim(
          sql`INSERT INTO yielded_oauth_client_assertion (namespace, assertion_id, expires_at_millis) VALUES (${namespace}, ${receipt.id}, ${receipt.expiresAtMillis})`,
          sql`ON CONFLICT (namespace, assertion_id) DO NOTHING RETURNING assertion_id`,
        );
      }, failure),
      get: Effect.fn("OAuthServerPersistence.get")(function* (namespace, id) {
        yield* standalone;

        const rows =
          yield* sql`SELECT payload, version, revoked FROM yielded_oauth_server WHERE namespace = ${namespace} AND grant_id = ${id}`;

        if (rows.length === 0) return undefined;
        if (rows.length !== 1) return yield* Unavailable.make({});
        const row = yield* Schema.decodeUnknownEffect(Row)(rows[0]);
        const record = yield* Schema.decodeEffect(codec)(row.payload);

        if (record.version !== row.version) return yield* Unavailable.make({});

        return row.revoked === 1 ? { ...record, status: "Revoked" as const } : record;
      }, failure),
      insert: Effect.fn("OAuthServerPersistence.insert")(function* (namespace, id, record) {
        yield* standalone;
        const payload = yield* Schema.encodeEffect(codec)(record);

        yield* requireFit(namespace, id);

        return yield* claim(
          sql`INSERT INTO yielded_oauth_server (namespace, grant_id, version, revoked, expires_at_millis, payload) VALUES (${namespace}, ${id}, ${record.version}, ${record.status === "Revoked" ? 1 : 0}, ${record.expiresAtMillis}, ${payload})`,
          sql`ON CONFLICT (namespace, grant_id) DO NOTHING RETURNING version`,
        );
      }, failure),
      compareAndSet: Effect.fn("OAuthServerPersistence.compareAndSet")(function* (
        namespace,
        id,
        version,
        record,
      ) {
        yield* standalone;
        if (version === record.version) return yield* Unavailable.make({});
        const payload = yield* Schema.encodeEffect(codec)(record);

        const update = sql`UPDATE yielded_oauth_server SET version = ${record.version}, revoked = ${record.status === "Revoked" ? 1 : 0}, expires_at_millis = ${record.expiresAtMillis}, payload = ${payload} WHERE namespace = ${namespace} AND grant_id = ${id} AND version = ${version} AND revoked = 0`;

        const changed = yield* sql.onDialectOrElse({
          mysql: () => executeSqlChange(sql, update),
          orElse: () => sql`${update} RETURNING version`.pipe(Effect.map((rows) => rows.length)),
        });

        return changed === 1;
      }, failure),
      revoke: Effect.fn("OAuthServerPersistence.revoke")(function* (namespace, id) {
        yield* standalone;
        yield* sql`UPDATE yielded_oauth_server SET revoked = 1 WHERE namespace = ${namespace} AND grant_id = ${id}`;
      }, failure),
    });
  }),
);

export const OAuthServerPersistence = { migrations, mysqlMigrations, layer };
