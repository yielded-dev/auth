import { OAuthUnavailable } from "@yielded/auth/OAuth";
import { Persistence, Record } from "@yielded/auth/OAuthApp";
import { Effect, Layer, Option, Schema } from "effect";
import { SqlClient } from "effect/unstable/sql";

const codec = Schema.fromJsonString(Record);
const Row = Schema.Struct({ payload: Schema.String, version: Schema.String });

/** Apply with the application's migrations. SQLite (including D1) and PostgreSQL.
 * Each transition is one conditional statement, so D1 needs no interactive
 * transaction and parallel workers share the same refresh/code claim.
 */
const migration = `CREATE TABLE yielded_oauth_app (
  namespace TEXT NOT NULL,
  record_key TEXT NOT NULL,
  version TEXT NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY (namespace, record_key)
)`;

const layer = Layer.effect(
  Persistence,
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    if (!sql.onDialectOrElse({ sqlite: () => true, pg: () => true, orElse: () => false }))
      return yield* OAuthUnavailable.make({});

    const noTransaction = Effect.gen(function* () {
      if (Option.isSome(yield* Effect.serviceOption(sql.transactionService)))
        return yield* OAuthUnavailable.make({});
    });

    const failure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
      effect.pipe(Effect.mapError(() => OAuthUnavailable.make({})));

    return Persistence.of({
      get: Effect.fn("OAuthAppPersistence.get")(function* (namespace, key) {
        yield* noTransaction;

        const rows = yield* sql<{
          payload: string;
          version: string;
        }>`SELECT payload, version FROM yielded_oauth_app WHERE namespace = ${namespace} AND record_key = ${key}`;

        if (rows.length === 0) return undefined;
        if (rows.length !== 1) return yield* OAuthUnavailable.make({});
        const row = yield* Schema.decodeEffect(Row)(rows[0]);
        const value = yield* Schema.decodeEffect(codec)(row.payload);

        if (value.version !== row.version) return yield* OAuthUnavailable.make({});

        return value;
      }, failure),
      insert: Effect.fn("OAuthAppPersistence.insert")(function* (namespace, key, value) {
        yield* noTransaction;
        const payload = yield* Schema.encodeEffect(codec)(value);

        const rows =
          yield* sql`INSERT INTO yielded_oauth_app (namespace, record_key, version, payload) VALUES (${namespace}, ${key}, ${value.version}, ${payload}) ON CONFLICT (namespace, record_key) DO NOTHING RETURNING version`;

        return rows.length === 1;
      }, failure),
      compareAndSet: Effect.fn("OAuthAppPersistence.compareAndSet")(function* (
        namespace,
        key,
        version,
        value,
      ) {
        yield* noTransaction;
        if (value.version === version) return yield* OAuthUnavailable.make({});
        const payload = yield* Schema.encodeEffect(codec)(value);

        const rows =
          yield* sql`UPDATE yielded_oauth_app SET version = ${value.version}, payload = ${payload} WHERE namespace = ${namespace} AND record_key = ${key} AND version = ${version} RETURNING version`;

        return rows.length === 1;
      }, failure),
    });
  }),
);

export const OAuthAppPersistence = { layer, migration };
