import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { PasswordUnavailable } from "@yielded/auth/Password";
import { PhoneOtpUnavailable } from "@yielded/auth/PhoneOtp";
import { Config, Effect, Layer, Schema } from "effect";
import { SqlClient, type SqlError } from "effect/unstable/sql";

import { HashingLive } from "../../../../shared/account/hashing";
import { AppAuth, Claims } from "./auth";
import { DeliveryLive } from "./delivery";
import { MigrationsLive } from "./migrations";
import { Persistence, storage } from "./schema";
import { customerId, seed } from "./seed";

// The persistence adapter requires SqlClient, and detects its PostgreSQL/SQLite
// dialect. Swap this Layer for SqliteClient (Node) or PgClient in a real service.
const DatabaseLive = Layer.unwrap(
  Effect.gen(function* () {
    const dialect = yield* Config.literals(["sqlite", "pg"], "PERSISTENCE_DIALECT").pipe(
      Config.withDefault("sqlite"),
    );

    const database: Layer.Layer<SqlClient.SqlClient, SqlError.SqlError> =
      dialect === "pg" ? PgliteClient.layer({}) : SqliteClient.layer({ filename: ":memory:" });

    return database;
  }),
);

const ConfigLive = Persistence.Config.layer(storage);

const DatabaseReady = MigrationsLive.pipe(
  Layer.provideMerge(ConfigLive),
  Layer.provideMerge(DatabaseLive),
);

const SeededDatabase = Layer.effectDiscard(seed).pipe(
  Layer.provideMerge(DatabaseReady),
  Layer.provideMerge(HashingLive),
);

const ClaimsLive = Layer.unwrap(
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    const active = sql.onDialectOrElse({ pg: () => true, orElse: () => 1 });

    const claims = (subjectId: string) =>
      sql`select display_name as "displayName" from customers where customer_key = ${subjectId} and enabled = ${active}`.pipe(
        Effect.flatMap((rows) =>
          rows.length === 1
            ? Schema.decodeUnknownEffect(Claims)(rows[0]).pipe(
                Effect.mapError(() => PasswordUnavailable.make({})),
              )
            : Effect.fail(PasswordUnavailable.make({})),
        ),
        Effect.mapError(() => PasswordUnavailable.make({})),
      );

    return Layer.mergeAll(
      Layer.succeed(AppAuth.strategies.password.ClaimsForPassword, {
        resolve: (credential) => claims(credential.revision.subjectId),
      }),
      Layer.succeed(AppAuth.strategies.phone.ClaimsForPhone, {
        resolve: (credential) =>
          claims(credential.revision.subjectId).pipe(
            Effect.mapError(() => PhoneOtpUnavailable.make({})),
          ),
      }),
    );
  }),
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(Persistence.layer),
  Layer.provide(ClaimsLive),
  Layer.provideMerge(DeliveryLive),
  Layer.provideMerge(SeededDatabase),
);

export const disableCustomer = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const disabled = sql.onDialectOrElse({ pg: () => false, orElse: () => 0 });

  yield* sql.withTransaction(
    sql`update customers set enabled = ${disabled}, auth_revision = 'customer-r2' where customer_key = ${customerId}`,
  );
});
