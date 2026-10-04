import type { AnyRelations } from "drizzle-orm";
import type { EffectPgDatabase } from "drizzle-orm/effect-postgres";
import type { AnyPgTable } from "drizzle-orm/pg-core";

import { Database } from "./pg-database";
import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./phone-target";

export const { makePhonePersistenceServices, coordinatePhonePersistence } = makePhoneTarget<
  Database,
  EffectPgDatabase<AnyRelations>,
  AnyPgTable<{ dialect: "pg" }>
>(Database, {
  mode: "interactive",
  dialect: "pg",
  locking: true,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
});
