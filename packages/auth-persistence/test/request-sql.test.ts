import { NodeCrypto } from "@effect/platform-node";
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { it } from "@effect/vitest";
import { Auth, Password, Sessions } from "@yielded/auth";
import { SubjectId } from "@yielded/auth/Schema";
import { Context, Effect, Layer, Schema } from "effect";
import { Reactivity } from "effect/reactivity";
import { SqlClient, Statement } from "effect/sql";
import { ConnectionError, SqlError } from "effect/sql/SqlError";
import { expect } from "vite-plus/test";

import { AuthPersistence } from "../src/index";

const app = Auth.make("test/request-sql", {
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

const persistence = AuthPersistence.make(app);

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

const RequestClient = Context.Reference<SqlClient.SqlClient | undefined>("test/RequestClient", {
  defaultValue: () => undefined,
});

const requestSql = Layer.effect(
  SqlClient.SqlClient,
  SqlClient.make({
    compiler: Statement.makeCompilerSqlite(),
    spanAttributes: [],
    acquirer: Effect.gen(function* () {
      const client = yield* RequestClient;

      if (client === undefined)
        return yield* new SqlError({
          reason: new ConnectionError({ cause: "No request SQL client" }),
        });

      return yield* client.reserve;
    }),
  }),
).pipe(Layer.provide(Reactivity.layer));

const capture = Effect.flatMap(Sessions.AuthenticationAuthority, (authority) =>
  authority.capture(SubjectId.make("member"), []),
);

// https://github.com/yielded-dev/auth/issues/200: the first lazy build dropped
// request services; subsequent operations must also use their own connection.
it.effect("preserves request-local SQL during initialization and across concurrent requests", () =>
  Effect.gen(function* () {
    const first = yield* SqliteClient.make({ filename: ":memory:" });
    const second = yield* SqliteClient.make({ filename: ":memory:" });

    yield* migrate("first").pipe(Effect.provideService(SqlClient.SqlClient, first));
    yield* migrate("second").pipe(Effect.provideService(SqlClient.SqlClient, second));

    const services = yield* Layer.build(
      persistence.layer.pipe(
        Layer.provide(persistence.Config.layer(storage)),
        Layer.provide(requestSql),
        Layer.provide(NodeCrypto.layer),
      ),
    );

    const read = (client: SqlClient.SqlClient) =>
      capture.pipe(Effect.provide(services), Effect.provideService(RequestClient, client));

    expect((yield* read(first)).revision.securityRevision).toBe("first");
    const results = yield* Effect.all([read(first), read(second)], { concurrency: 2 });

    expect(results.map((result) => result.revision.securityRevision)).toEqual(["first", "second"]);
    expect((yield* capture.pipe(Effect.provide(services), Effect.result))._tag).toBe("Failure");
  }).pipe(Effect.provide(Reactivity.layer)),
);

// Explicit request: runtime skip must avoid catalog reads, while standalone
// validation must still detect migration drift without requiring crypto.
it.effect("skips runtime catalog probes and validates physical storage independently", () =>
  Effect.gen(function* () {
    const sql = yield* SqliteClient.make({ filename: ":memory:" });

    yield* migrate("current").pipe(Effect.provideService(SqlClient.SqlClient, sql));
    const runtime = AuthPersistence.make(app, { validation: "skip" });
    const config = runtime.Config.layer(storage);

    const services = yield* Layer.build(
      runtime.layer.pipe(
        Layer.provide(config),
        Layer.provide(requestSql),
        Layer.provide(NodeCrypto.layer),
      ),
    );

    const rejectCatalog = (statement: Statement.Statement<unknown>) => {
      const [query] = statement.compile();

      return /sqlite_schema|pragma_|pg_catalog|pg_attribute|information_schema/i.test(query)
        ? Effect.die("Runtime queried the physical catalog")
        : Effect.succeed(statement);
    };

    expect(
      (yield* capture.pipe(
        Effect.provide(services),
        Effect.provideService(RequestClient, sql),
        Effect.provideService(Statement.CurrentTransformer, rejectCatalog),
      )).revision.securityRevision,
    ).toBe("current");
    yield* sql`drop table request_auth_credentials`;
    yield* sql`create table request_auth_credentials (credential_id text, subject_id text, revision text, active integer)`;

    const validate = runtime.validate.pipe(
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
