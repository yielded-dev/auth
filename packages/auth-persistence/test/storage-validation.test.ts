import { NodeCrypto } from "@effect/platform-node";
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { it } from "@effect/vitest";
import { Auth, Password, Sessions } from "@yielded/auth";
import { SubjectId } from "@yielded/auth/Schema";
import { Effect, Layer, Schema } from "effect";
import { Reactivity } from "effect/reactivity";
import { SqlClient, Statement } from "effect/sql";
import { expect } from "vite-plus/test";

import { AuthPersistence } from "../src/index";

const app = Auth.make("test/storage-validation", {
  claims: Schema.Struct({}),
  strategies: { password: Password.make() },
  sessions: Sessions.stateful(),
});

const subjects = AuthPersistence.table({
  name: "subjects",
  columns: {
    id: { name: "id", type: "text" },
    active: { name: "active", type: "boolean" },
    revision: { name: "revision", type: "text" },
  },
  unique: [["id"]],
});

const requirement = Sessions.AuthenticationRequirement.make({
  alternatives: [
    {
      factors: ["knowledge"],
      minimumCredentials: 1,
      userVerified: false,
      phishingResistant: false,
    },
  ],
  maximumAgeMillis: 60_000,
});

const persistence = AuthPersistence.make(app, { validation: "skip" });

const storage = persistence.managed({
  prefix: "request_auth",
  subjects: {
    table: subjects,
    id: "id",
    status: "active",
    activeValue: true,
    securityRevision: "revision",
    idCodec: SubjectId,
    requirements: () => Effect.succeed(requirement),
  },
});

const quote = (name: string) => '"' + name.replaceAll('"', '""') + '"';

const migrate = Effect.fnUntraced(function* (revision: string) {
  const sql = yield* SqlClient.SqlClient;

  for (const table of [subjects, ...Object.values(storage.schema)]) {
    const columns = Object.values(table.columns).map(
      ({ options }) =>
        `${quote(options.name)} ${options.type === "text" ? "text" : "integer"}${options.nullable ? "" : " not null"}`,
    );

    const keys = table.unique.map(
      (key) => `unique (${key.map((name) => quote(table.columns[name].options.name)).join(", ")})`,
    );

    yield* sql.unsafe(`create table ${quote(table.name)} (${[...columns, ...keys].join(", ")})`);
  }
  yield* sql`insert into subjects values ('member', 1, ${revision})`;
});

const capture = Effect.flatMap(Sessions.AuthenticationAuthority, (authority) =>
  authority.capture(SubjectId.make("member"), []),
);

// Explicit request: runtime skip must avoid catalog reads, while standalone
// validation must still detect migration drift without requiring crypto.
it.effect("skips runtime catalog probes and validates physical storage independently", () =>
  Effect.gen(function* () {
    const sql = yield* SqliteClient.make({ filename: ":memory:" });

    yield* migrate("current").pipe(Effect.provideService(SqlClient.SqlClient, sql));
    const config = persistence.Config.layer(storage);

    const PersistenceLive = persistence.layer.pipe(
      Layer.provide(config),
      Layer.provide(NodeCrypto.layer),
    );

    const rejectCatalog = (statement: Statement.Statement<unknown>) => {
      const [query] = statement.compile();

      return /sqlite_schema|pragma_|pg_catalog|pg_attribute|information_schema/i.test(query)
        ? Effect.die("Runtime queried the physical catalog")
        : Effect.succeed(statement);
    };

    expect(
      (yield* capture.pipe(
        Effect.provide(PersistenceLive, { local: true }),
        Effect.provideService(SqlClient.SqlClient, sql),
        Effect.provideService(Statement.CurrentTransformer, rejectCatalog),
      )).revision.securityRevision,
    ).toBe("current");
    yield* sql`drop table request_auth_credentials`;
    yield* sql`create table request_auth_credentials (credential_id text, subject_id text, revision text, active integer)`;

    const validate = persistence.validate.pipe(
      Effect.provide(config),
      Effect.provideService(SqlClient.SqlClient, sql),
    );

    expect((yield* Effect.result(validate))._tag).toBe("Failure");
    yield* sql`create unique index credential_key on request_auth_credentials (credential_id)`;
    yield* validate;
    yield* sql`drop index credential_key`;
    expect((yield* Effect.result(validate))._tag).toBe("Failure");
  }).pipe(Effect.provide(Reactivity.layer)),
);
