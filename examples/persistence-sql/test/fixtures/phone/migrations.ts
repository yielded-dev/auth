import { Effect, Layer } from "effect";
import { SqlClient } from "effect/unstable/sql";

import { MigrationsLive as AccountMigrations } from "../../../src/migrations";

export const MigrationsLive = Layer.effectDiscard(
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    yield* sql`create table if not exists app_phone_state (
      c_scope text not null unique, c_state text not null, c_version text not null
    )`;
  }),
).pipe(Layer.provide(AccountMigrations));
