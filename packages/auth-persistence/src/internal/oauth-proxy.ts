import { FlowContext, Persistence, Record, Unavailable } from "@yielded/auth/OAuthProxy";
import { Effect, Layer, Schema } from "effect";
import { SqlClient } from "effect/sql";

import { requireStandalone } from "./standalone";

const codec = Schema.fromJsonString(Record);
const contextCodec = Schema.fromJsonString(FlowContext);

const Row = Schema.Struct({
  payload: Schema.String,
  version: Schema.String,
  stage: Schema.String,
  context: Schema.String,
  expiry: Schema.String,
  deadline: Schema.NullOr(Schema.String),
});

/** SQLite/D1 and PostgreSQL; apply once through application migrations.
 * Retain terminal records until expires_at_millis, then expired rows may be deleted.
 * Context and stage columns guard each standalone transition without a prior read.
 */
const migration = `CREATE TABLE yielded_oauth_proxy (
  namespace TEXT NOT NULL,
  flow_id TEXT NOT NULL,
  version TEXT NOT NULL,
  stage TEXT NOT NULL CHECK (stage IN ('Pending', 'Exchanging', 'Ready', 'Consumed')),
  context TEXT NOT NULL,
  expires_at_millis BIGINT NOT NULL,
  handoff_expires_at_millis BIGINT,
  payload TEXT NOT NULL,
  PRIMARY KEY (namespace, flow_id),
  CHECK ((stage = 'Ready' AND handoff_expires_at_millis IS NOT NULL)
    OR (stage <> 'Ready' AND handoff_expires_at_millis IS NULL))
)`;

const layer = Layer.effect(
  Persistence,
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    if (!sql.onDialectOrElse({ sqlite: () => true, pg: () => true, orElse: () => false }))
      return yield* Unavailable.make({});
    const standalone = requireStandalone(() => Unavailable.make({}), sql.transactionService);

    const failure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
      effect.pipe(Effect.mapError(() => Unavailable.make({})));

    const clock = sql.onDialectOrElse({
      sqlite: () => sql.literal("CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)"),
      orElse: () => sql.literal("CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS BIGINT)"),
    });

    return Persistence.of({
      get: Effect.fnUntraced(function* (namespace, id) {
        yield* standalone;

        const rows = yield* sql`SELECT payload, version, stage, context,
          CAST(expires_at_millis AS TEXT) AS expiry,
          CAST(handoff_expires_at_millis AS TEXT) AS deadline
          FROM yielded_oauth_proxy WHERE namespace = ${namespace} AND flow_id = ${id}`;

        if (rows.length === 0) return undefined;
        if (rows.length !== 1) return yield* Unavailable.make({});
        const row = yield* Schema.decodeUnknownEffect(Row)(rows[0]);
        const record = yield* Schema.decodeEffect(codec)(row.payload);
        const context = yield* Schema.encodeEffect(contextCodec)(record.context);

        if (
          record.context.id !== id ||
          record.version !== row.version ||
          record._tag !== row.stage ||
          context !== row.context ||
          String(record.context.expiresAtMillis) !== row.expiry ||
          (record._tag === "Ready" ? String(record.handoffExpiresAtMillis) : null) !== row.deadline
        )
          return yield* Unavailable.make({});

        return record;
      }, failure),
      insert: Effect.fnUntraced(function* (namespace, record) {
        yield* standalone;
        if (record._tag !== "Pending") return yield* Unavailable.make({});
        const payload = yield* Schema.encodeEffect(codec)(record);
        const context = yield* Schema.encodeEffect(contextCodec)(record.context);

        const rows = yield* sql`INSERT INTO yielded_oauth_proxy
          (namespace, flow_id, version, stage, context, expires_at_millis, payload)
          SELECT ${namespace}, ${record.context.id}, ${record.version}, ${record._tag},
            ${context}, ${record.context.expiresAtMillis}, ${payload}
          WHERE ${record.context.expiresAtMillis} > ${clock}
          ON CONFLICT (namespace, flow_id) DO NOTHING RETURNING version`;

        return rows.length === 1;
      }, failure),
      compareAndSet: Effect.fnUntraced(function* (namespace, version, record) {
        yield* standalone;
        if (version === record.version || record._tag === "Pending")
          return yield* Unavailable.make({});

        // Explicitly omit private envelopes from both irreversible marker stages.
        const payload = yield* Schema.encodeEffect(codec)(
          record._tag === "Ready"
            ? record
            : { _tag: record._tag, version: record.version, context: record.context },
        );

        const context = yield* Schema.encodeEffect(contextCodec)(record.context);

        const previous =
          record._tag === "Exchanging"
            ? "Pending"
            : record._tag === "Ready"
              ? "Exchanging"
              : "Ready";

        const deadline = record._tag === "Ready" ? record.handoffExpiresAtMillis : null;

        const consume =
          record._tag === "Consumed"
            ? sql`AND handoff_expires_at_millis > ${clock}`
            : sql.literal("");

        const rows = yield* sql`UPDATE yielded_oauth_proxy
          SET version = ${record.version}, stage = ${record._tag},
            handoff_expires_at_millis = ${deadline}, payload = ${payload}
          WHERE namespace = ${namespace} AND flow_id = ${record.context.id}
            AND version = ${version} AND stage = ${previous} AND context = ${context}
            AND expires_at_millis = ${record.context.expiresAtMillis}
            AND expires_at_millis > ${clock} ${consume}
          RETURNING version`;

        return rows.length === 1;
      }, failure),
    });
  }),
);

export const OAuthProxyPersistence = { migration, layer };
