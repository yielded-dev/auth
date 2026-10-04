import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteBunDatabase } from "drizzle-orm/effect-sqlite-bun";
import { Context } from "effect";

/** The application-owned Drizzle database used to construct persistence services. */
export class Database extends Context.Service<Database, EffectSQLiteBunDatabase<AnyRelations>>()(
  "effect-auth/persistence-drizzle/SqliteBun/Database",
) {}
