import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import { Effect } from "effect";

import { Database } from "./sqlite-do-database";
import { makeSqlitePasswordPreparedTarget } from "./sqlite-password-prepared";
import { sqlitePasswordConfiguration } from "./sqlite-passwords";

export const { makePasswordPreparedPersistenceServices, coordinatePasswordPreparedPersistence } =
  makeSqlitePasswordPreparedTarget<Database, EffectSQLiteDoDatabase<AnyRelations>, true>(
    Database,
    sqlitePasswordConfiguration("synchronous", Effect.void, Effect.void),
  );
