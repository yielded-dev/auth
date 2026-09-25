import * as LibsqlClient from "@effect/sql-libsql/LibsqlClient";
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { it } from "@effect/vitest";
import * as OAuthCrypto from "@yielded/auth-crypto/OAuth";
import { OAuthUnavailable } from "@yielded/auth/OAuth";
import * as OAuthApp from "@yielded/auth/OAuthApp";
import { SubjectId } from "@yielded/auth/Schema";
import * as Strava from "@yielded/auth/Strava";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { Deferred, Effect, Encoding, Exit, Fiber, Layer, Logger, Redacted, Schema } from "effect";
import { TestClock } from "effect/testing";
import { HttpClient, HttpClientResponse } from "effect/unstable/http";
import { SqlClient } from "effect/unstable/sql";
import { expect } from "vite-plus/test";

import { OAuthAppPersistence } from "../src/internal/oauth-app";

const app = OAuthApp.make("strava-test", {
  claims: Schema.Struct({ role: Schema.Literal("member"), athleteId: Schema.Int }),
  returnTargets: ["/sync"],
});

const origin = "https://app.example.com";

const keys = (byte: number) => ({
  activeKeyId: "key",
  keys: [
    { id: "key", material: Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32).fill(byte))) },
  ],
});

const sessionConfig = { origin, sessionKeys: keys(1) };

const database = Layer.effectDiscard(
  Effect.gen(function* () {
    yield* (yield* SqlClient.SqlClient).unsafe(OAuthAppPersistence.migration);
  }),
).pipe(Layer.provideMerge(SqliteClient.layer({ filename: ":memory:" })));

const durable = OAuthAppPersistence.layer.pipe(Layer.provideMerge(database));

const harness = (
  settings: {
    failedRefresh?: boolean;
    unknownGrantCommit?: boolean;
    onRequest?: (operation: string) => Effect.Effect<void>;
  } = {},
) => {
  const requests: string[] = [];
  const signals: AbortSignal[] = [];

  const client = HttpClient.make((request, url, signal) =>
    Effect.gen(function* () {
      const body =
        request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "";

      const form = new URLSearchParams(body);
      const operation = form.get("grant_type") ?? url.pathname;

      requests.push(operation);
      signals.push(signal);
      if (settings.onRequest) yield* settings.onRequest(operation);
      if (settings.failedRefresh && operation === "refresh_token")
        return yield* Effect.die("provider disconnected after consuming refresh token");

      const payload = url.pathname.endsWith("athlete")
        ? { id: 123 }
        : {
            token_type: "Bearer",
            access_token: operation === "refresh_token" ? "second-access" : "first-access",
            refresh_token: operation === "refresh_token" ? "second-refresh" : "first-refresh",
            expires_at: operation === "refresh_token" ? 43200 : 21600,
            athlete: { id: 123, firstname: "Pat" },
            scope: "activity:read_all",
          };

      return HttpClientResponse.fromWeb(
        request,
        new Response(JSON.stringify(payload), { headers: { "content-type": "application/json" } }),
      );
    }),
  );

  const storage = settings.unknownGrantCommit
    ? Layer.effect(
        OAuthApp.Persistence,
        Effect.gen(function* () {
          const persistence = yield* OAuthApp.Persistence;

          return OAuthApp.Persistence.of({
            ...persistence,
            insert: (namespace, key, value) =>
              persistence
                .insert(namespace, key, value)
                .pipe(
                  Effect.flatMap((saved) =>
                    key.startsWith("grant/") && saved
                      ? Effect.fail(OAuthUnavailable.make({}))
                      : Effect.succeed(saved),
                  ),
                ),
          });
        }),
      ).pipe(Layer.provideMerge(durable))
    : durable;

  const live = app
    .layer({
      ...sessionConfig,

      provider: Strava.provider({
        clientId: "1234",
        clientSecret: Redacted.make("client-secret"),
        scopes: ["activity:read_all"],
      }),
    })
    .pipe(
      Layer.provide(OAuthCrypto.transactionLayer(keys(2))),
      Layer.provide(OAuthCrypto.connectedTokenLayer(keys(3))),
      Layer.provide(layerWebCrypto),
      Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
      Layer.provide(
        Layer.succeed(app.Accounts, {
          resolve: ({ identity }) =>
            Effect.succeed({
              subjectId: SubjectId.make(`athlete-${identity.subject}`),
              claims: { role: "member" as const, athleteId: 123 },
            }),
        }),
      ),
      Layer.provideMerge(storage),
    );

  return { live, requests, signals };
};

const start = Effect.gen(function* () {
  const service = yield* app.Service;
  const begin = yield* service.handle(new Request(`${origin}${app.paths.signIn}`));

  expect(begin.status).toBe(302);
  const location = new URL(begin.headers.get("location")!);
  const cookie = begin.headers.getSetCookie()[0].split(";")[0];
  const callback = `${origin}${app.paths.callback}?code=authorization-code&state=${location.searchParams.get("state")}&scope=activity%3Aread_all`;

  return { service, cookie, callback };
});

const signIn = Effect.gen(function* () {
  const started = yield* start;

  const response = yield* started.service.handle(
    new Request(started.callback, { headers: { cookie: started.cookie } }),
  );

  expect(response.status).toBe(302);

  const issued = response.headers
    .getSetCookie()
    .find((value) => value.startsWith(`${app.cookieName}=`))!;

  const cookie = issued.split(";")[0];
  const credential = Redacted.make(cookie.slice(cookie.indexOf("=") + 1));
  const verifier = yield* app.Sessions;
  const session = yield* verifier.verify(credential);

  return { ...started, session };
});

it.effect("an uncertain refresh is never repeated, including after the attempt deadline", () => {
  const h = harness({ failedRefresh: true });
  const logs: Array<string> = [];

  const logger = Logger.make((entry) =>
    logs.push(JSON.stringify(Logger.formatStructured.log(entry))),
  );

  return Effect.gen(function* () {
    const signedIn = yield* signIn;

    yield* TestClock.adjust("6 hours");

    const first = yield* Effect.exit(
      signedIn.service.withAccessToken(signedIn.session, () => Effect.void),
    );

    expect(Exit.isFailure(first)).toBe(true);
    yield* TestClock.adjust("1 hour");

    const second = yield* Effect.exit(
      signedIn.service.withAccessToken(signedIn.session, () => Effect.void),
    );

    expect(Exit.isFailure(second)).toBe(true);
    expect(h.requests.filter((value) => value === "refresh_token")).toHaveLength(1);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("Auth oauth-app failed");
    expect(logs[0]).not.toContain("provider disconnected after consuming refresh token");
  }).pipe(Effect.provide([h.live, Logger.layer([logger])]));
});

for (const [name, client] of [
  ["SQLite", SqliteClient.layer({ filename: ":memory:" })],
  ["libSQL", LibsqlClient.layer({ url: "file::memory:" })],
] as const) {
  it.effect(`${name} persistence rejects ambient transactions`, () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;

      yield* sql.unsafe(OAuthAppPersistence.migration);
      const persistence = yield* OAuthApp.Persistence;

      // Never expose a successful storage result before an outer owner's commit.
      const error = yield* sql
        .withTransaction(persistence.get("strava-test", "missing"))
        .pipe(Effect.flip);

      expect(error._tag).toBe("OAuthUnavailable");
    }).pipe(Effect.provide(OAuthAppPersistence.layer), Effect.provide(client)),
  );
}

it.effect(
  "a lost grant-commit response issues no session and cannot repeat the authorization code",
  () => {
    const h = harness({ unknownGrantCommit: true });

    return Effect.gen(function* () {
      const started = yield* start;

      const response = yield* started.service.handle(
        new Request(started.callback, { headers: { cookie: started.cookie } }),
      );

      expect(response.status).toBe(503);
      expect(response.headers.getSetCookie()).toHaveLength(0);
      const sql = yield* SqlClient.SqlClient;

      const grants =
        yield* sql`SELECT record_key FROM yielded_oauth_app WHERE record_key LIKE 'grant/%'`;

      expect(grants).toHaveLength(1);

      const replay = yield* started.service.handle(
        new Request(started.callback, { headers: { cookie: started.cookie } }),
      );

      expect(replay.status).toBe(400);
      expect(h.requests.filter((value) => value === "authorization_code")).toHaveLength(1);
    }).pipe(Effect.provide(h.live));
  },
);

it.effect(
  "a stalled callback times out, closes its provider work, and cannot be exchanged again",
  () =>
    Effect.gen(function* () {
      const entered = yield* Deferred.make<void>();
      const finalized = yield* Deferred.make<void>();

      const h = harness({
        onRequest: () =>
          Deferred.succeed(entered, undefined).pipe(
            Effect.andThen(Effect.never),
            Effect.ensuring(Deferred.succeed(finalized, undefined)),
          ),
      });

      yield* Effect.gen(function* () {
        const started = yield* start;

        const fiber = yield* started.service
          .handle(new Request(started.callback, { headers: { cookie: started.cookie } }))
          .pipe(Effect.forkChild);

        yield* Deferred.await(entered);
        yield* TestClock.adjust("31 seconds");
        expect((yield* Fiber.join(fiber)).status).toBe(503);
        expect(yield* Deferred.isDone(finalized)).toBe(true);
        expect(h.signals.every((signal) => signal.aborted)).toBe(true);

        const replay = yield* started.service.handle(
          new Request(started.callback, { headers: { cookie: started.cookie } }),
        );

        expect(replay.status).toBe(400);
        expect(h.requests).toEqual(["authorization_code"]);
      }).pipe(Effect.provide(h.live));
    }),
);

it.effect(
  "concurrent refresh callers exchange once, and disconnect prevents a late refresh from restoring access",
  () =>
    Effect.gen(function* () {
      const entered = yield* Deferred.make<void>();
      const proceed = yield* Deferred.make<void>();

      const h = harness({
        onRequest: (operation) =>
          operation === "refresh_token"
            ? Deferred.succeed(entered, undefined).pipe(Effect.andThen(Deferred.await(proceed)))
            : Effect.void,
      });

      yield* Effect.gen(function* () {
        const signedIn = yield* signIn;

        yield* TestClock.adjust("6 hours");
        let uses = 0;

        const access = signedIn.service.withAccessToken(signedIn.session, () =>
          Effect.sync(() => {
            uses++;
          }),
        );

        const first = yield* access.pipe(Effect.forkChild);

        yield* Deferred.await(entered);
        expect(Exit.isFailure(yield* Effect.exit(access))).toBe(true);
        yield* signedIn.service.disconnect(signedIn.session);
        yield* Deferred.succeed(proceed, undefined);
        expect(Exit.isFailure(yield* Effect.exit(Fiber.join(first)))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(access))).toBe(true);
        expect(uses).toBe(0);
        expect(h.requests.filter((value) => value === "refresh_token")).toHaveLength(1);
      }).pipe(Effect.provide(h.live));
    }),
);
