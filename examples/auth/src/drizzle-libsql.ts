import { NodeRuntime } from "@effect/platform-node";
import * as LibsqlClient from "@effect/sql-libsql/LibsqlClient";
import { makeAuthServices } from "@yielded/auth-persistence/drizzle/libsql";
import * as Drizzle from "drizzle-orm/effect-libsql";
import { Effect } from "effect";

import { mapping, verify } from "./drizzle-sqlite-node";

Effect.gen(function* () {
  const sql = yield* LibsqlClient.LibsqlClient;
  const db = yield* Drizzle.makeWithDefaults({});

  yield* verify("effect-libsql", sql, makeAuthServices(db, mapping));
}).pipe(
  Effect.provide(LibsqlClient.layer({ url: "file::memory:" })),
  Effect.scoped,
  NodeRuntime.runMain,
);
