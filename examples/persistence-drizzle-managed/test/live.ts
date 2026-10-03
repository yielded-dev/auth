import { BunHttpServer, BunRuntime, BunServices } from "@effect/platform-bun";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { Client, Http, Password, EmailDelivery, Proofs } from "@yielded/auth";
import { ConfigProvider, Context, Effect, FileSystem, Layer, Redacted } from "effect";
import { FetchHttpClient, HttpRouter } from "effect/http";
import { SqlClient } from "effect/sql";

import { AppAuth } from "../../shared/account/auth";
import { AuthApi } from "../../shared/account/contract";
import { ProofIngressLive } from "../../shared/account/proof-ingress";
import { DatabaseLive, KeysLive } from "../src/data";
import { AuthLive } from "../src/live";

const assert: (condition: unknown, message: string) => asserts condition = (condition, message) => {
  if (!condition) throw new Error(message);
};

const origin = "http://localhost:4181";
const email = "customer@example.invalid";
const password = "indigo42";

const program = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem;
  const directory = yield* fs.makeTempDirectoryScoped();
  const cookies = new Map<string, string>();

  const delivery = Layer.succeed(EmailDelivery.EmailDelivery, { send: () => Effect.void });

  const application = AuthLive.pipe(
    Layer.provide([
      DatabaseLive,
      KeysLive,
      delivery,
      ProofIngressLive,
      Layer.succeed(Password.CompromisedPasswords, {
        check: () => Effect.succeed({ _tag: "Allowed" }),
      }),
    ]),
    Layer.provide(
      Layer.succeed(
        ConfigProvider.ConfigProvider,
        ConfigProvider.fromUnknown({ AUTH_DATA_DIR: directory }),
      ),
    ),
    Layer.provide(BunServices.layer),
  );

  // In-process Web Requests have no socket peer; this host owns their identity.
  const caller = HttpRouter.middleware<{ provides: Proofs.ProofRequestContext }>()((handler) =>
    handler.pipe(
      Effect.provideService(Proofs.ProofRequestContext, {
        networkKey: Redacted.make("managed-example-test"),
      }),
    ),
  );

  const routes = Http.make(AppAuth, {
    origin,
    cookie: { secure: false, prefix: "managed-example-" },
  })
    .routes()
    .pipe(
      Layer.provide(caller.layer),
      Layer.provide(application),
      Layer.provide(BunHttpServer.layerHttpServices),
    );

  const open = Effect.acquireRelease(
    Effect.sync(() => HttpRouter.toWebHandler(Layer.fresh(routes), { disableLogger: true })),
    (web) => Effect.promise(() => web.dispose()),
  );

  const sql = <A, E, R>(query: Effect.Effect<A, E, R>) =>
    query.pipe(Effect.provide(SqliteClient.layer({ filename: `${directory}/auth.sqlite` })));

  const fetchFor =
    (web: Effect.Success<typeof open>, jar = cookies): typeof globalThis.fetch =>
    async (input, init) => {
      const request = new Request(input, init);
      const headers = new Headers(request.headers);

      headers.set("origin", origin);
      headers.set("cookie", [...jar].map(([name, value]) => `${name}=${value}`).join("; "));
      const response = await web.handler(new Request(request, { headers }));

      for (const header of response.headers.getSetCookie()) {
        const pair = header.split(";", 1)[0];
        const equals = pair.indexOf("=");
        const name = pair.slice(0, equals);
        const value = pair.slice(equals + 1);

        if (value === "") jar.delete(name);
        else jar.set(name, value);
      }

      return response;
    };

  const api = Effect.fn("test.client")(function* (web: Effect.Success<typeof open>, jar = cookies) {
    const client = Client.make(AuthApi, { baseUrl: origin });

    const context = yield* Layer.build(
      client.layerFetch.pipe(
        Layer.provide(Layer.succeed(FetchHttpClient.Fetch, fetchFor(web, jar))),
      ),
    );

    return Context.get(context, client).auth;
  });

  yield* Effect.scoped(
    Effect.gen(function* () {
      const call = yield* api(yield* open);

      const submission = {
        requestId: "first-registration",
        email,
        newPassword: password,
        registration: { displayName: "Ada" },
      };

      const registered = yield* call.register(submission);

      assert(
        registered._tag === "RegistrationAccepted",
        "Registration failed from an empty database",
      );
      // An application insert must roll back if credential storage fails afterward.
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          yield* db`create trigger reject_password before insert on customer_auth_passwords begin select raise(abort, 'test rejection'); end`;
        }),
      );

      const failed = yield* call
        .register({
          ...submission,
          requestId: "rolled-back",
          email: "rollback@example.invalid",
          registration: { displayName: "Rollback" },
        })
        .pipe(Effect.result);

      assert(failed._tag === "Failure", "Credential write failure was accepted");
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          yield* db`drop trigger reject_password`;
          const rows = yield* db`select * from customers`;

          assert(rows.length === 1, "Failed registration left an orphan customer");

          const receipts =
            yield* db`select * from customer_auth_passwordRegistrations where request_id = 'rolled-back'`;

          assert(receipts.length === 0, "A failed registration left a committed receipt");
        }),
      );
    }),
  );
  yield* Effect.log("Failed credential storage rolled back the customer and registration receipt.");
});

if (import.meta.main)
  BunRuntime.runMain(program.pipe(Effect.scoped, Effect.provide(BunServices.layer)));
