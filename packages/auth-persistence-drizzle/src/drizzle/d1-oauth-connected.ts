import type { D1Client } from "@effect/sql-d1/D1Client";
import type { AnyRelations } from "drizzle-orm";
import type { EffectSQLiteD1Database } from "drizzle-orm/effect-d1";
import type { AnySQLiteTable } from "drizzle-orm/sqlite-core";
import { Effect } from "effect";

import { Database } from "./d1-database";
import { makeD1OAuthConnectedTarget } from "./oauth-connected-drivers";
import type { OAuthD1Mapping } from "./oauth-model";

export const {
  makeOAuthConnectedServices,
  makeOAuthConnectedRevocationServices,
  coordinateOAuthConnected,
  coordinateOAuthConnectedRevocations,
} = makeD1OAuthConnectedTarget<
  Database,
  EffectSQLiteD1Database<AnyRelations> & { readonly $client: D1Client },
  AnySQLiteTable<{ dialect: "sqlite" }>,
  OAuthD1Mapping
>(Database, {
  mode: "batch",
  dialect: "sqlite",
  locking: false,
  standaloneGuard: () => Effect.void,
});
