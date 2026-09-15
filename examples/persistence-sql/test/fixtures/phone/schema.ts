import { AuthPersistence } from "@yielded/auth-persistence";
import { SubjectId } from "@yielded/auth/Schema";
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

const phoneState = AuthPersistence.table({
  name: "app_phone_state",
  columns: {
    scope: { name: "c_scope", type: "text" },
    state: { name: "c_state", type: "text" },
    version: { name: "c_version", type: "text" },
  },
  unique: [["scope"]],
});

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
