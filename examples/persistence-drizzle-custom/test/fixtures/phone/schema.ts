import { AuthPersistence } from "@yielded/auth-persistence/drizzle/sqlite-bun";
import { SubjectId } from "@yielded/auth/Schema";
import { sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";
import { Effect } from "effect";

import {
  customers,
  identifiers,
  credentials,
  passwords,
  passwordAttempts,
  passwordScopes,
  passwordCharges,
  passwordCommands,
  proofRequests,
  proofSeries,
  proofGenerations,
  proofContinuations,
  proofScopes,
  proofAbuse,
  proofFailures,
  proofCommands,
  sessions,
  sessionFlows,
} from "../../../src/tables";
import { AppAuth, requirement } from "./auth";
export { customers } from "../../../src/tables";

export const phoneState = sqliteTable(
  "app_phone_state",
  {
    scope: text("c_scope").notNull(),
    state: text("c_state").notNull(),
    version: text("c_version").notNull(),
  },
  (table) => [uniqueIndex("app_phone_state_key_0").on(table.scope)],
);

export const Persistence = AuthPersistence.make(AppAuth);

export const storage = Persistence.map({
  subjects: {
    table: customers,
    id: "id",
    status: "enabled",
    activeValue: true,
    securityRevision: "securityRevision",
    idCodec: SubjectId,
    requirements: () => Effect.succeed(requirement),
  },
  tables: {
    identifiers,
    credentials,
    passwords,
    passwordAttempts,
    passwordScopes,
    passwordCharges,
    passwordCommands,
    phoneState,
    proofRequests,
    proofSeries,
    proofGenerations,
    proofContinuations,
    proofScopes,
    proofAbuse,
    proofFailures,
    proofCommands,
    sessions,
    sessionFlows,
  },
});
