import { NodeRuntime } from "@effect/platform-node";
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { makeAuthServices } from "@yielded/auth-persistence/drizzle/sqlite-node";
import * as Drizzle from "drizzle-orm/effect-sqlite-node";
import { Effect } from "effect";

import { mapping, verify } from "./drizzle-sqlite-node";

Effect.gen(function* () {
  const sql = yield* SqliteClient.SqliteClient;
  const db = yield* Drizzle.makeWithDefaults({});

  yield* verify("effect-sqlite-node", sql, makeAuthServices(db, mapping));
}).pipe(
  Effect.provide(SqliteClient.layer({ filename: ":memory:" })),
  Effect.scoped,
  NodeRuntime.runMain,
);
