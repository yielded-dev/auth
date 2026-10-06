import { makeOAuthKernel, type OAuthKernel } from "@yielded/auth-persistence/Adapter";
import { is } from "drizzle-orm";
import { MySqlTable } from "drizzle-orm/mysql-core";
import { PgTable } from "drizzle-orm/pg-core";

import { drizzleQueryOperations } from "./query-operations";

export const oauthKernel: OAuthKernel = makeOAuthKernel(drizzleQueryOperations, (table) =>
  is(table, MySqlTable) ? "mysql" : is(table, PgTable) ? "pg" : "sqlite",
);
