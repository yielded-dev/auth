import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";
import { Context } from "effect";

/** The application-owned Drizzle database used to construct persistence services. */
export class Database extends Context.Service<Database, EffectLibsqlDatabase<AnyRelations>>()(
  "effect-auth/persistence-drizzle/Libsql/Database",
) {}
