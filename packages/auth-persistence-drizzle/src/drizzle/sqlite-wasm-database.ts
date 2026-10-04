import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteWasmDatabase } from "drizzle-orm/effect-sqlite-wasm";
import { Context } from "effect";

/** The application-owned Drizzle database used to construct persistence services. */
export class Database extends Context.Service<Database, EffectSQLiteWasmDatabase<AnyRelations>>()(
  "effect-auth/persistence-drizzle/SqliteWasm/Database",
) {}
