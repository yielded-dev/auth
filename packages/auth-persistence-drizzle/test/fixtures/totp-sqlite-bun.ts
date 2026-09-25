import { BunRuntime } from "@effect/platform-bun";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import { TotpSecretKeys } from "@yielded/auth/Totp";
import type { AnyRelations } from "drizzle-orm";
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Effect, Layer } from "effect";

import { makeTotpTarget, sqlClientTotpStandaloneGuard } from "../../src/drizzle/totp-target";
import { exampleKeys, mapping, migrate, useAuthenticator } from "./totp-sqlite-consumer";

const target = makeTotpTarget<EffectSQLiteBunDatabase<AnyRelations>, AnySQLiteTable>({
  mode: "interactive",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: sqlClientTotpStandaloneGuard,
});

Effect.gen(function* () {
  const client = yield* SqliteClient.SqliteClient,
    database = yield* Drizzle.makeWithDefaults({});

  yield* migrate(client);
  const services = yield* target.makeTotpPersistenceServices(database, mapping);
  const result = yield* useAuthenticator(services.totpPersistence);

  yield* Effect.log(result);
}).pipe(
  Effect.provideService(TotpSecretKeys, exampleKeys),
  Effect.provide(
    Layer.mergeAll(LifecycleHooks.empty, SqliteClient.layer({ filename: ":memory:" })),
  ),
  Effect.scoped,
  BunRuntime.runMain,
);
