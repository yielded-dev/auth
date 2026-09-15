import { NodeRuntime } from "@effect/platform-node";
import * as SqliteClient from "@effect/sql-sqlite-wasm/SqliteClient";
import { makeAuthServices } from "@yielded/auth-persistence/drizzle/sqlite-wasm";
import * as Drizzle from "drizzle-orm/effect-sqlite-wasm";
import { Effect } from "effect";

import { mapping, verify } from "./drizzle-sqlite-node";

Effect.gen(function* () {
  const sql = yield* SqliteClient.SqliteClient;
  const db = yield* Drizzle.makeWithDefaults({});

  yield* verify("effect-sqlite-wasm", sql, makeAuthServices(db, mapping));
}).pipe(Effect.provide(SqliteClient.layerMemory({})), Effect.scoped, NodeRuntime.runMain);
