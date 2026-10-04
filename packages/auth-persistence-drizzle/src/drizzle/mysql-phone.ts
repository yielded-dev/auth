import type { AnyRelations } from "drizzle-orm";
import type { EffectMysql2Database } from "drizzle-orm/effect-mysql2";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core";

import { Database } from "./mysql-database";
import { unavailable as phoneUnavailable } from "./phone-state";
import { makePhoneTarget, sqlClientPhoneStandaloneGuard } from "./phone-target";
import { mysqlTransaction } from "./transaction-mysql";

export const { makePhonePersistenceServices, coordinatePhonePersistence } = makePhoneTarget<
  Database,
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>(Database, {
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientPhoneStandaloneGuard,
  transaction: (database, body) => mysqlTransaction(phoneUnavailable, database, body),
});
