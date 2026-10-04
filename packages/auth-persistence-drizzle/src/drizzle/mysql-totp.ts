import type { AnyRelations } from "drizzle-orm";
import type { EffectMysql2Database } from "drizzle-orm/effect-mysql2";
import type { AnyMySqlTable } from "drizzle-orm/mysql-core";

import { Database } from "./mysql-database";
import { unavailable as totpUnavailable } from "./totp-state";
import { makeTotpTarget, sqlClientTotpStandaloneGuard } from "./totp-target";
import { mysqlTransaction } from "./transaction-mysql";

export const { makeTotpPersistenceServices, coordinateTotpPersistence } = makeTotpTarget<
  Database,
  EffectMysql2Database<AnyRelations>,
  AnyMySqlTable<{ dialect: "mysql" }>
>(Database, {
  mode: "interactive",
  dialect: "mysql",
  locking: true,
  standaloneGuard: sqlClientTotpStandaloneGuard,
  transaction: (database, body) => mysqlTransaction(totpUnavailable, database, body),
});
