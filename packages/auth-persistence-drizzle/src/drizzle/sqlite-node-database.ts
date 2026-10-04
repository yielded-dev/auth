import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteNodeDatabase } from "drizzle-orm/effect-sqlite-node";
import { Context } from "effect";

/** The application-owned Drizzle database used to construct persistence services. */
export class Database extends Context.Service<Database, EffectSQLiteNodeDatabase<AnyRelations>>()(
  "effect-auth/persistence-drizzle/SqliteNode/Database",
) {}
