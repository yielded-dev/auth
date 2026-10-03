import { BunHttpServer, BunRuntime, BunServices } from "@effect/platform-bun";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { Client, Http, Password, EmailDelivery, Passkey } from "@yielded/auth";
import { ConfigProvider, Context, Effect, FileSystem, Layer, Schema } from "effect";
import { FetchHttpClient, HttpRouter } from "effect/http";
import { SqlClient } from "effect/sql";

import { AppAuth } from "../../shared/account/auth";
import { AuthApi } from "../../shared/account/contract";
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

  const routes = Http.make(AppAuth, {
    origin,
    cookie: { secure: false, prefix: "managed-example-" },
  })
    .routes()
    .pipe(Layer.provide(application), Layer.provide(BunHttpServer.layerHttpServices));

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

      // The hardening request requires fresh proof before a session can add a credential.
      const signedIn = yield* call.passwordSignIn({ email, password });

      assert(signedIn._tag === "Authenticated", "Password sign-in failed");

      const enrollment = {
        flowId: "fresh-enrollment",
        commandId: "fresh-enrollment",
        profileId: "default",
        name: "My passkey",
      };

      yield* call.enrollPasskey(enrollment);
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          // Age the whole session consistently while retaining the database's real clock.
          yield* db`update customer_auth_sessions set
            issued_at = issued_at - 300001,
            expires_at = expires_at - 300001,
            absolute_expires_at = absolute_expires_at - 300001,
            record = json_set(record,
            '$.provenance.evidence.proofs[0].verifiedAt',
            json_extract(record, '$.provenance.evidence.proofs[0].verifiedAt') - 300001,
            '$.assurance.evidence[0].verifiedAt',
            json_extract(record, '$.assurance.evidence[0].verifiedAt') - 300001,
            '$.assurance.authenticatedAt',
            json_extract(record, '$.assurance.authenticatedAt') - 300001,
            '$.issuedAt', json_extract(record, '$.issuedAt') - 300001,
            '$.expiresAt', json_extract(record, '$.expiresAt') - 300001,
            '$.absoluteExpiresAt', json_extract(record, '$.absoluteExpiresAt') - 300001)`;
        }),
      );
      assert((yield* call.getSession()) !== null, "An older valid session stopped working");
      yield* call.listPasskeys({ limit: 5 });

      const stale = yield* call
        .enrollPasskey({ ...enrollment, flowId: "older-session", commandId: "older-session" })
        .pipe(Effect.result);

      assert(
        stale._tag === "Failure" && Schema.is(Passkey.PasskeyActionRequired)(stale.failure),
        "An older session was allowed to enroll a new passkey",
      );
      yield* Effect.log("An older valid session can read but must sign in again to add a passkey.");
    }),
  );
  yield* Effect.log("Failed credential storage rolled back the customer and registration receipt.");
});

if (import.meta.main)
  BunRuntime.runMain(program.pipe(Effect.scoped, Effect.provide(BunServices.layer)));
