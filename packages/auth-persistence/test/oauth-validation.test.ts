import { NodeCrypto } from "@effect/platform-node";
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { it } from "@effect/vitest";
import { hooksLayer } from "@yielded/auth/Persistence";
import { Effect, Layer } from "effect";
import { SqlClient, Statement } from "effect/sql";
import { expect } from "vite-plus/test";

import * as OAuthPersistence from "../src/OAuthPersistence";

const ownership = OAuthPersistence.table({
  name: "ownership",
  columns: {
    identityKey: { name: "identity_key", type: "text" },
    subjectId: { name: "subject_id", type: "text" },
    provider: { name: "provider", type: "text" },
    issuer: { name: "issuer", type: "text" },
    externalSubject: { name: "external_subject", type: "text" },
  },
  unique: [["identityKey"]],
});

const intents = OAuthPersistence.table({
  name: "intents",
  columns: {
    moduleId: { name: "module_id", type: "text" },
    reference: { name: "reference", type: "text" },
    flowId: { name: "flow_id", type: "text" },
    identityKey: { name: "identity_key", type: "text", nullable: true },
    snapshot: { name: "snapshot", type: "text", nullable: true },
    expiresAt: { name: "expires_at", type: "integer", nullable: true },
    retentionUntil: { name: "retention_until", type: "integer", nullable: true },
  },
  unique: [
    ["moduleId", "reference"],
    ["moduleId", "flowId"],
  ],
});

const mapping = {
  ownership: {
    table: ownership,
    identityKey: "identityKey",
    subjectId: "subjectId",
    provider: "provider",
    issuer: "issuer",
    externalSubject: "externalSubject",
    decodeSubjectId: (row) => String(row.subjectId),
  },
  intent: {
    table: intents,
    moduleId: "moduleId",
    reference: "reference",
    flowId: "flowId",
    identityKey: "identityKey",
    snapshot: "snapshot",
    expiresAt: "expiresAt",
    retentionUntil: "retentionUntil",
    encodeInsert: () => ({}),
  },
  clock: OAuthPersistence.clock,
  constraints: {
    ownership: "unique(ownership.identityKey)",
    intentReference: "unique(intent.moduleId,intent.reference)",
    intentFlow: "unique(intent.moduleId,intent.flowId)",
  },
  eligible: () => OAuthPersistence.sql`true`,
} satisfies OAuthPersistence.OAuthRegistrationIntentMapping<
  typeof ownership,
  typeof intents,
  string
>;

// https://github.com/yielded-dev/auth/issues/200: explicit OAuth mappings must be
// constructible before a request exists, with physical validation moved to deploy/CI.
it.effect("separates explicit OAuth validation from runtime construction", () =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const rejectSql = () => Effect.die("Construction accessed SQL before a request existed");

    yield* OAuthPersistence.makeOAuthRegistrationIntentServices(mapping, {
      validation: "skip",
    }).pipe(Effect.provideService(Statement.CurrentTransformer, rejectSql));
    expect(
      (yield* Effect.result(OAuthPersistence.makeOAuthRegistrationIntentServices(mapping)))._tag,
    ).toBe("Failure");
    yield* sql`create table ownership (identity_key text, subject_id text, provider text, issuer text, external_subject text)`;
    yield* sql`create table intents (module_id text, reference text, flow_id text, identity_key text, snapshot text, expires_at integer, retention_until integer, unique(module_id, reference), unique(module_id, flow_id))`;
    expect((yield* Effect.result(OAuthPersistence.validate(mapping)))._tag).toBe("Failure");
    yield* sql`create unique index ownership_identity on ownership (identity_key)`;
    yield* OAuthPersistence.validate(mapping);
    yield* OAuthPersistence.makeOAuthRegistrationIntentServices(mapping);
  }).pipe(
    Effect.provide(
      Layer.mergeAll(SqliteClient.layer({ filename: ":memory:" }), NodeCrypto.layer, hooksLayer),
    ),
  ),
);
