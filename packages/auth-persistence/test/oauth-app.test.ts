import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { it } from "@effect/vitest";
import * as GitHub from "@yielded/auth/GitHub";
import { OAuthRejected, OAuthUnavailable } from "@yielded/auth/OAuth";
import * as OAuthApp from "@yielded/auth/OAuthApp";
import { SubjectId } from "@yielded/auth/Schema";
import * as Strava from "@yielded/auth/Strava";
import { Deferred, Effect, Encoding, Exit, Fiber, Layer, Redacted, Schema } from "effect";
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

it.effect(
  "the managed GitHub example signs in with PKCE and retains refreshable API access",
  () => {
    const origin = "http://localhost:3000";

    const github = OAuthApp.make("github", {
      claims: Schema.Struct({ name: Schema.String }),
      returnTargets: ["/account"],
    });

    const exchanges: Array<URLSearchParams> = [];

    const storage = Layer.effectDiscard(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;

        yield* sql.unsafe(OAuthAppPersistence.migration);
      }),
    ).pipe(Layer.provideMerge(SqliteClient.layer({ filename: ":memory:" })));

    const live = github
      .layer({
        ...sessionConfig,
        origin,
        transactionKeys: keys(2),
        tokenKeys: keys(3),
        provider: GitHub.appProvider({
          clientId: "github-example",
          clientSecret: Redacted.make("github-example-secret"),
          fetch: async (url, init) => {
            if (url === "https://api.github.com/user")
              return Response.json({ id: 123, login: "example", name: "Example User" });
            if (url !== "https://github.com/login/oauth/access_token")
              throw new Error("Unexpected provider request");
            const form = init.body instanceof URLSearchParams ? init.body : new URLSearchParams();

            exchanges.push(new URLSearchParams(form));
            const refreshing = form.get("grant_type") === "refresh_token";

            return Response.json({
              access_token: refreshing ? "github-second-access" : "github-first-access",
              refresh_token: refreshing ? "github-second-refresh" : "github-first-refresh",
              expires_in: 28800,
              refresh_token_expires_in: 15897600,
              token_type: "bearer",
              scope: "read:user",
            });
          },
        }),
      })
      .pipe(
        Layer.provide(OAuthAppPersistence.layer.pipe(Layer.provide(storage))),
        Layer.provide(
          Layer.succeed(github.Accounts, {
            resolve: (verified) =>
              Effect.succeed({
                subjectId: SubjectId.make(`github:${verified.identity.subject}`),
                claims: { name: verified.profile?.displayName ?? "" },
              }),
          }),
        ),
      );

    return Effect.gen(function* () {
      const service = yield* github.Service;
      const start = yield* service.handle(new Request(`${origin}${github.paths.signIn}`));

      expect(start.status).toBe(302);
      const authorization = new URL(start.headers.get("location")!);

      expect(authorization.searchParams.get("scope")).toBe("read:user offline_access");
      expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authorization.searchParams.get("redirect_uri")).toBe(
        `${origin}${github.paths.callback}`,
      );

      const query = new URLSearchParams({
        code: "github-code",
        state: authorization.searchParams.get("state")!,
        iss: "https://github.com/login/oauth",
      });

      const callback = new Request(`${origin}${github.paths.callback}?${query}`, {
        headers: { cookie: start.headers.getSetCookie()[0].split(";")[0] },
      });

      const completed = yield* service.handle(callback);

      expect(completed.status).toBe(302);

      const cookie = completed.headers
        .getSetCookie()
        .find((value) => value.startsWith(`${github.cookieName}=`))!;

      const credential = Redacted.make(cookie.split(";")[0].slice(github.cookieName.length + 1));
      const session = yield* (yield* github.Sessions).verify(credential);

      expect(session.subjectId).toBe("github:123");
      expect(session.claims.name).toBe("Example User");
      expect(exchanges[0].get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
      expect((yield* service.handle(callback)).status).toBe(400);
      yield* TestClock.adjust("8 hours");

      const token = yield* service.withAccessToken(session, (token) =>
        Effect.succeed(Redacted.value(token)),
      );

      expect(token).toBe("github-second-access");
      expect(exchanges.map((form) => form.get("grant_type"))).toEqual([
        "authorization_code",
        "refresh_token",
      ]);
      expect(exchanges[1].get("refresh_token")).toBe("github-first-refresh");
    }).pipe(Effect.provide(live));
  },
);

const harness = (
  settings: {
    denied?: boolean;
    failedRefresh?: boolean;
    interruptedExchange?: boolean;
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
      if (settings.interruptedExchange && operation === "authorization_code")
        return yield* Effect.interrupt;
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

  const database = SqliteClient.layer({ filename: ":memory:" });

  const migrated = Layer.effectDiscard(
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;

      yield* sql.unsafe(OAuthAppPersistence.migration);
    }),
  ).pipe(Layer.provideMerge(database));

  const durable = OAuthAppPersistence.layer.pipe(Layer.provideMerge(migrated));

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
      transactionKeys: keys(2),
      tokenKeys: keys(3),
      provider: Strava.provider({
        clientId: "1234",
        clientSecret: Redacted.make("client-secret"),
        scopes: ["activity:read_all"],
      }),
    })
    .pipe(
      Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
      Layer.provide(
        Layer.succeed(app.Accounts, {
          resolve: ({ identity }) =>
            settings.denied
              ? Effect.fail(OAuthRejected.make({}))
              : Effect.succeed({
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
  expect(response.headers.get("location")).toBe(`${origin}/sync`);

  const issued = response.headers
    .getSetCookie()
    .find((value) => value.startsWith(`${app.cookieName}=`))!;

  expect(issued).toContain("HttpOnly");
  expect(issued).toContain("Secure");
  const cookie = issued.split(";")[0];
  const credential = Redacted.make(cookie.slice(cookie.indexOf("=") + 1));
  const verifier = yield* app.Sessions;
  const session = yield* verifier.verify(credential);

  return { ...started, session, sessionCookie: cookie, credential };
});

it.effect(
  "one guest authorization establishes a stateless session and an encrypted, refreshable connection",
  () => {
    const h = harness();

    return Effect.gen(function* () {
      const signedIn = yield* signIn;

      expect(signedIn.session.claims).toEqual({ role: "member", athleteId: 123 });
      expect(signedIn.session.expiresAtMillis - signedIn.session.issuedAtMillis).toBe(
        30 * 24 * 60 * 60 * 1000,
      );
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{ payload: string }>`SELECT payload FROM yielded_oauth_app`;

      expect(JSON.stringify(rows)).not.toContain("first-access");
      expect(JSON.stringify(rows)).not.toContain("first-refresh");

      const replay = yield* signedIn.service.handle(
        new Request(signedIn.callback, { headers: { cookie: signedIn.cookie } }),
      );

      expect(replay.status).toBe(400);
      expect(h.requests.filter((value) => value === "authorization_code")).toHaveLength(1);
      yield* TestClock.adjust("6 hours");

      const token = yield* signedIn.service.withAccessToken(signedIn.session, (value) =>
        Effect.succeed(Redacted.value(value)),
      );

      expect(token).toBe("second-access");
      expect(h.requests.filter((value) => value === "refresh_token")).toHaveLength(1);
      expect(h.signals.every((signal) => signal.aborted)).toBe(true);
      yield* sql`DROP TABLE yielded_oauth_app`;

      // This verifier is constructed without persistence, provider, or Accounts.
      const verified = yield* Effect.gen(function* () {
        return yield* (yield* app.Sessions).verify(signedIn.credential);
      }).pipe(Effect.provide(app.sessionLayer(sessionConfig)));

      expect(verified.subjectId).toBe("athlete-123");
      yield* TestClock.adjust("30 days");
      expect(
        Exit.isFailure(yield* Effect.exit((yield* app.Sessions).verify(signedIn.credential))),
      ).toBe(true);
    }).pipe(Effect.provide(h.live));
  },
);

it.effect("rejects an unbound callback and unsafe return target before contacting Strava", () => {
  const h = harness();

  return Effect.gen(function* () {
    const started = yield* start;
    const missing = yield* started.service.handle(new Request(started.callback));

    expect(missing.status).toBe(400);

    const wrong = yield* started.service.handle(
      new Request(started.callback, {
        headers: { cookie: `${started.cookie.slice(0, -43)}${"a".repeat(43)}` },
      }),
    );

    expect(wrong.status).toBe(400);

    const redirect = yield* started.service.handle(
      new Request(`${origin}${app.paths.signIn}?returnTo=https://attacker.example`),
    );

    expect(redirect.status).toBe(400);
    expect(h.requests).toHaveLength(0);
  }).pipe(Effect.provide(h.live));
});

it.effect("an application denial never installs a connection or issues a session", () => {
  const h = harness({ denied: true });

  return Effect.gen(function* () {
    const started = yield* start;

    const response = yield* started.service.handle(
      new Request(started.callback, { headers: { cookie: started.cookie } }),
    );

    expect(response.status).toBe(400);
    expect(response.headers.getSetCookie()).toHaveLength(0);
    const sql = yield* SqlClient.SqlClient;

    const grants =
      yield* sql`SELECT record_key FROM yielded_oauth_app WHERE record_key LIKE 'grant/%'`;

    expect(grants).toHaveLength(0);
  }).pipe(Effect.provide(h.live));
});

it.effect("an uncertain refresh is never repeated, including after the attempt deadline", () => {
  const h = harness({ failedRefresh: true });

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
  }).pipe(Effect.provide(h.live));
});

it.effect(
  "an interrupted exchange burns the flow and leaves no session or plaintext secrets",
  () => {
    const h = harness({ interruptedExchange: true });

    return Effect.gen(function* () {
      const started = yield* start;

      expect(
        Exit.isFailure(
          yield* Effect.exit(
            started.service.handle(
              new Request(started.callback, { headers: { cookie: started.cookie } }),
            ),
          ),
        ),
      ).toBe(true);

      const replay = yield* started.service.handle(
        new Request(started.callback, { headers: { cookie: started.cookie } }),
      );

      expect(replay.status).toBe(400);
      expect(h.requests.filter((value) => value === "authorization_code")).toHaveLength(1);
      expect(h.signals.every((signal) => signal.aborted)).toBe(true);
    }).pipe(Effect.provide(h.live));
  },
);

it.effect("persistence rejects ambient transactions before any provider exchange", () => {
  const h = harness();

  return Effect.gen(function* () {
    const persistence = yield* OAuthApp.Persistence;
    const started = yield* start;
    // The normal storage contract rejects ambient transactions, so a caller
    // cannot obtain a session from a grant write it later rolls back.
    const sql = yield* SqlClient.SqlClient;

    const outcome = yield* Effect.exit(
      sql.withTransaction(persistence.get("strava-test", "missing")),
    );

    expect(Exit.isFailure(outcome)).toBe(true);
    expect(h.requests).toHaveLength(0);
    expect(started.callback).toContain("state=");
  }).pipe(Effect.provide(h.live));
});

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
        // Disconnect is provider-access policy; this signed session still verifies.
        expect((yield* (yield* app.Sessions).verify(signedIn.credential)).subjectId).toBe(
          "athlete-123",
        );
      }).pipe(Effect.provide(h.live));
    }),
);
