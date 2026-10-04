import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteDoDatabase } from "drizzle-orm/effect-sqlite-do";
import { Context } from "effect";

/** The application-owned Drizzle database used to construct persistence services. */
export class Database extends Context.Service<Database, EffectSQLiteDoDatabase<AnyRelations>>()(
  "effect-auth/persistence-drizzle/SqliteDo/Database",
) {}
