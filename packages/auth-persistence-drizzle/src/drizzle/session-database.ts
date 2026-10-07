import { Context } from "effect";

import type { NativeSqlDatabase } from "./native-database";

/** Native SQL authority for the current transaction or savepoint. */
export class CurrentSessionSql extends Context.Service<CurrentSessionSql, NativeSqlDatabase>()(
  "effect-auth/drizzle/CurrentSessionSql",
) {}
