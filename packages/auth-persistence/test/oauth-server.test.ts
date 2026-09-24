import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { it } from "@effect/vitest";
import * as OAuthServer from "@yielded/auth/OAuthServer";
import { SubjectId } from "@yielded/auth/Schema";
import {
  Cause,
  Clock,
  Deferred,
  Effect,
  Encoding,
  Exit,
  Fiber,
  Layer,
  Logger,
  Redacted,
  Schema,
} from "effect";
import { TestClock } from "effect/testing";
import { McpProtocol, McpServer, Tool, Toolkit } from "effect/unstable/ai";
import { HttpRouter, HttpServerRequest } from "effect/unstable/http";
import { SqlClient } from "effect/unstable/sql";
import { expect } from "vite-plus/test";

import { OAuthServerPersistence } from "../src/internal/oauth-server";

const server = OAuthServer.make("mcp", { scopes: ["read", "write"] });
const origin = "https://app.example.com";
const resource = `${origin}/mcp`;
const redirectUri = "https://client.example.com/callback";
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const config: OAuthServer.Options = {
  origin,
  resource,
  loginPath: "/login",
  clients: [
    { clientId: "client", name: "Example <client>", redirectUris: [redirectUri] },
    { clientId: "another", name: "Another client", redirectUris: [redirectUri] },
  ],
  keys: {
    activeKeyId: "v1",
    keys: [
      { id: "v1", material: Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32).fill(9))) },
    ],
  },
};

const harness = (
  dialect: "sqlite" | "pg" = "sqlite",
  fault?: (operation: string) => Effect.Effect<void, OAuthServer.Unavailable>,
) => {
  const database = Layer.effectDiscard(
    Effect.gen(function* () {
      yield* (yield* SqlClient.SqlClient).unsafe(OAuthServerPersistence.migration);
    }),
  ).pipe(
    Layer.provideMerge(
      dialect === "sqlite" ? SqliteClient.layer({ filename: ":memory:" }) : PgliteClient.layer({}),
    ),
  );

  const storage = OAuthServerPersistence.layer.pipe(Layer.provideMerge(database));

  const durable = fault
    ? Layer.effect(
        OAuthServer.Persistence,
        Effect.gen(function* () {
          const store = yield* OAuthServer.Persistence;

          return OAuthServer.Persistence.of({
            ...store,
            compareAndSet: (namespace, id, version, record) =>
              Effect.gen(function* () {
                if (record.status === "Active") yield* fault("before");
                const saved = yield* store.compareAndSet(namespace, id, version, record);

                if (record.status === "Active" && saved) yield* fault("after");

                return saved;
              }),
          });
        }),
      ).pipe(Layer.provideMerge(storage))
    : storage;

  const identity = Layer.succeed(server.Identity, {
    current: Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      // Test-only identity authority. Production verifies an application session.
      const user = request.headers["test-user"];

      return user === undefined ? undefined : SubjectId.make(user);
    }),
  });

  return server.layer(config).pipe(Layer.provide(identity), Layer.provideMerge(durable));
};

const get = (path: string, cookie?: string, user = "alice") =>
  new Request(`${origin}${path}`, {
    headers: { "test-user": user, ...(cookie ? { cookie } : {}) },
  });

const post = (
  path: string,
  data: Record<string, string>,
  cookie?: string,
  user = "alice",
  requestOrigin = origin,
) =>
  new Request(`${origin}${path}`, {
    method: "POST",
    headers: { "test-user": user, origin: requestOrigin, ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams(data),
  });

const body = <S extends Schema.Top>(response: Response, schema: S) =>
  Effect.promise(() => response.json()).pipe(Effect.flatMap(Schema.decodeUnknownEffect(schema)));

const Tokens = Schema.Struct({
  access_token: Schema.String,
  refresh_token: Schema.String,
  scope: Schema.String,
  token_type: Schema.Literal("Bearer"),
  expires_in: Schema.Int,
});

const consentToken = (html: string) => {
  const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1] ?? "";

  expect(csrf).not.toBe("");

  return csrf;
};

const start = (user = "alice", scope = "read") =>
  Effect.gen(function* () {
    const service = yield* server.Service;

    const query = new URLSearchParams({
      response_type: "code",
      client_id: "client",
      redirect_uri: redirectUri,
      resource,
      scope,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: "client-state",
    });

    const response = yield* service.handle(
      get(`${server.paths.authorize}?${query}`, undefined, user),
    );

    expect(response.status).toBe(303);
    const cookie = response.headers.getSetCookie()[0].split(";")[0];

    expect(response.headers.getSetCookie()[0]).toContain("Max-Age=300");
    const consent = yield* service.handle(get(server.paths.authorize, cookie, user));

    expect(consent.status).toBe(200);
    const html = yield* Effect.promise(() => consent.text());

    expect(html).toContain("Example &lt;client&gt;");

    return { service, cookie, csrf: consentToken(html), user };
  });

const authorize = (user = "alice", scope = "read") =>
  Effect.gen(function* () {
    const flow = yield* start(user, scope);

    const response = yield* flow.service.handle(
      post(server.paths.authorize, { csrf: flow.csrf, decision: "approve" }, flow.cookie, user),
    );

    expect(response.status).toBe(303);
    const redirect = new URL(response.headers.get("location")!);

    expect(redirect.origin).toBe("https://client.example.com");
    expect(redirect.searchParams.get("state")).toBe("client-state");
    expect(redirect.searchParams.get("iss")).toBe(origin);

    return { ...flow, code: redirect.searchParams.get("code")! };
  });

const exchange = (code: string, codeVerifier = verifier) =>
  post(server.paths.token, {
    grant_type: "authorization_code",
    client_id: "client",
    resource,
    redirect_uri: redirectUri,
    code,
    code_verifier: codeVerifier,
  });

const issue = (user = "alice", scope = "read") =>
  Effect.gen(function* () {
    const flow = yield* authorize(user, scope);
    const response = yield* flow.service.handle(exchange(flow.code));

    expect(response.status).toBe(200);

    return { ...flow, tokens: yield* body(response, Tokens) };
  });

const refresh = (token: string) =>
  post(server.paths.token, {
    grant_type: "refresh_token",
    client_id: "client",
    resource,
    refresh_token: token,
  });

for (const dialect of ["sqlite", "pg"] as const) {
  it.effect(
    `${dialect}: consent, PKCE, one-use codes, refresh replay and revocation share durable authority`,
    () =>
      Effect.gen(function* () {
        const flow = yield* authorize();

        expect((yield* flow.service.handle(exchange(flow.code, "x".repeat(43)))).status).toBe(400);
        const response = yield* flow.service.handle(exchange(flow.code));

        expect(response.status).toBe(200);
        const tokens = yield* body(response, Tokens);
        const access = yield* flow.service.verify(Redacted.make(tokens.access_token));

        expect(access).toMatchObject({
          subjectId: "alice",
          clientId: "client",
          resource,
          scopes: ["read"],
        });
        const rotatedResponse = yield* flow.service.handle(refresh(tokens.refresh_token));

        expect(rotatedResponse.status).toBe(200);
        const rotated = yield* body(rotatedResponse, Tokens);

        expect(
          Exit.isFailure(
            yield* Effect.exit(flow.service.verify(Redacted.make(tokens.access_token))),
          ),
        ).toBe(true);
        expect((yield* flow.service.handle(refresh(tokens.refresh_token))).status).toBe(400);
        expect(
          Exit.isFailure(
            yield* Effect.exit(flow.service.verify(Redacted.make(rotated.access_token))),
          ),
        ).toBe(true);
        const fresh = yield* issue();

        expect(
          (yield* fresh.service.handle(
            post(server.paths.revoke, { client_id: "client", token: fresh.tokens.refresh_token }),
          )).status,
        ).toBe(200);
        expect(
          Exit.isFailure(
            yield* Effect.exit(fresh.service.verify(Redacted.make(fresh.tokens.access_token))),
          ),
        ).toBe(true);
        const replay = yield* issue();

        expect((yield* replay.service.handle(exchange(replay.code))).status).toBe(400);
        expect(
          Exit.isFailure(
            yield* Effect.exit(replay.service.verify(Redacted.make(replay.tokens.access_token))),
          ),
        ).toBe(true);
        const sql = yield* SqlClient.SqlClient;
        const rows = yield* sql`SELECT payload FROM yielded_oauth_server`;

        expect(JSON.stringify(rows)).not.toContain(tokens.access_token);
        expect(JSON.stringify(rows)).not.toContain(tokens.refresh_token);
      }).pipe(Effect.provide(harness(dialect))),
  );
}

it.effect("browser consent is bound to the request, origin and authenticated subject", () =>
  Effect.gen(function* () {
    const flow = yield* start();

    for (const request of [
      post(server.paths.authorize, { csrf: flow.csrf, decision: "approve" }),
      post(server.paths.authorize, { csrf: "wrong", decision: "approve" }, flow.cookie),
      post(server.paths.authorize, { csrf: flow.csrf, decision: "approve" }, flow.cookie, "bob"),
      post(
        server.paths.authorize,
        { csrf: flow.csrf, decision: "approve" },
        flow.cookie,
        "alice",
        "https://evil.example",
      ),
    ]) {
      const response = yield* flow.service.handle(request);

      expect(response.status).toBe(400);
      expect(response.headers.has("location")).toBe(false);
    }

    const denied = yield* flow.service.handle(
      post(server.paths.authorize, { csrf: flow.csrf, decision: "deny" }, flow.cookie),
    );

    expect(new URL(denied.headers.get("location")!).searchParams.get("error")).toBe(
      "access_denied",
    );
    expect(
      (yield* flow.service.handle(
        post(server.paths.authorize, { csrf: flow.csrf, decision: "approve" }, flow.cookie),
      )).status,
    ).toBe(400);
    const expired = yield* authorize();

    yield* TestClock.adjust("61 seconds");
    expect((yield* expired.service.handle(exchange(expired.code))).status).toBe(400);
  }).pipe(Effect.provide(harness())),
);

it.effect("switching accounts invalidates previously rendered consent", () =>
  Effect.gen(function* () {
    const flow = yield* start("alice");
    const consent = yield* flow.service.handle(get(server.paths.authorize, flow.cookie, "bob"));

    expect(consent.status).toBe(200);
    const csrf = consentToken(yield* Effect.promise(() => consent.text()));

    const stale = yield* flow.service.handle(
      post(server.paths.authorize, { csrf: flow.csrf, decision: "approve" }, flow.cookie, "bob"),
    );

    expect(stale.status).toBe(400);
    expect(stale.headers.has("location")).toBe(false);

    const approved = yield* flow.service.handle(
      post(server.paths.authorize, { csrf, decision: "approve" }, flow.cookie, "bob"),
    );

    expect(approved.status).toBe(303);
    const code = new URL(approved.headers.get("location")!).searchParams.get("code")!;
    const tokens = yield* body(yield* flow.service.handle(exchange(code)), Tokens);
    const access = yield* flow.service.verify(Redacted.make(tokens.access_token));

    expect(access.subjectId).toBe("bob");
  }).pipe(Effect.provide(harness())),
);

it.effect("client, redirect and resource bindings reject cross-application credential use", () =>
  Effect.gen(function* () {
    const flow = yield* authorize();

    const fields = {
      grant_type: "authorization_code",
      client_id: "client",
      resource,
      redirect_uri: redirectUri,
      code: flow.code,
      code_verifier: verifier,
    };

    for (const replacement of [
      { client_id: "another" },
      { redirect_uri: "https://evil.example/callback" },
      { resource: `${origin}/other` },
    ]) {
      expect(
        (yield* flow.service.handle(post(server.paths.token, { ...fields, ...replacement })))
          .status,
      ).toBe(400);
    }
    const exchanged = yield* flow.service.handle(exchange(flow.code));
    const tokens = yield* body(exchanged, Tokens);

    const otherResource = server
      .layer({ ...config, resource: `${origin}/other` })
      .pipe(Layer.provide(Layer.succeed(server.Identity, { current: Effect.succeed(undefined) })));

    const crossResource = yield* Effect.gen(function* () {
      return yield* (yield* server.Service).verify(Redacted.make(tokens.access_token));
    }).pipe(Effect.exit, Effect.provide(otherResource));

    expect(Exit.isFailure(crossResource)).toBe(true);

    const invalid = new URLSearchParams({
      response_type: "code",
      client_id: "client",
      redirect_uri: "https://evil.example/callback",
      resource,
      scope: "read",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });

    const rejected = yield* flow.service.handle(get(`${server.paths.authorize}?${invalid}`));

    expect(rejected.status).toBe(400);
    expect(rejected.headers.has("location")).toBe(false);
    const sql = yield* SqlClient.SqlClient;

    const transaction = yield* sql
      .withTransaction(flow.service.verify(Redacted.make(tokens.access_token)))
      .pipe(Effect.exit);

    expect(Exit.isFailure(transaction)).toBe(true);

    const widened = yield* flow.service.handle(
      post(server.paths.token, {
        grant_type: "refresh_token",
        client_id: "client",
        resource,
        refresh_token: tokens.refresh_token,
        scope: "read write",
      }),
    );

    expect(widened.status).toBe(400);
  }).pipe(Effect.provide(harness())),
);

it.effect(
  "concurrent refresh never delivers two grants and a replay disables the winning token",
  () =>
    Effect.gen(function* () {
      const flow = yield* issue();

      const results = yield* Effect.all(
        [
          flow.service.handle(refresh(flow.tokens.refresh_token)),
          flow.service.handle(refresh(flow.tokens.refresh_token)),
        ],
        { concurrency: 2 },
      );

      expect(results.map((r) => r.status).sort()).toEqual([200, 400]);

      const tokens = yield* body(
        results.find((r) => r.status === 200)!,
        Tokens,
      );

      expect(
        Exit.isFailure(yield* Effect.exit(flow.service.verify(Redacted.make(tokens.access_token)))),
      ).toBe(true);
    }).pipe(Effect.provide(harness())),
);

it.effect("a lost issuance commit returns no credentials and cannot be reissued", () =>
  Effect.gen(function* () {
    const flow = yield* authorize();
    const response = yield* flow.service.handle(exchange(flow.code));

    expect(response.status).toBe(503);
    expect(yield* Effect.promise(() => response.text())).not.toContain("access_token");
    expect((yield* flow.service.handle(exchange(flow.code))).status).toBe(400);
  }).pipe(
    Effect.provide(
      harness("sqlite", (when) =>
        when === "after" ? Effect.fail(OAuthServer.Unavailable.make({})) : Effect.void,
      ),
    ),
  ),
);

it.effect("defects are scrubbed and interruption/timeout finalize in-flight issuance", () =>
  Effect.gen(function* () {
    const logs: string[] = [];

    const logger = Logger.make((entry) =>
      logs.push(JSON.stringify(Logger.formatStructured.log(entry))),
    );

    yield* Effect.gen(function* () {
      const flow = yield* authorize();

      expect((yield* flow.service.handle(exchange(flow.code))).status).toBe(503);
    }).pipe(
      Effect.provide([
        harness("sqlite", () => Effect.die("private-token-marker")),
        Logger.layer([logger]),
      ]),
    );
    expect(logs.join(" ")).not.toContain("private-token-marker");
    expect(logs.length).toBeGreaterThan(0);
    for (const timeout of [false, true]) {
      const started = yield* Deferred.make<void>();
      let finalized = false;

      yield* Effect.gen(function* () {
        const flow = yield* authorize();
        const fiber = yield* flow.service.handle(exchange(flow.code)).pipe(Effect.forkChild);

        yield* Deferred.await(started);
        if (timeout) {
          yield* TestClock.adjust("31 seconds");
          expect((yield* Fiber.join(fiber)).status).toBe(503);
        } else {
          yield* Fiber.interrupt(fiber);
          const exit = yield* Fiber.await(fiber);

          expect(Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause)).toBe(true);
        }
        expect(finalized).toBe(true);
      }).pipe(
        Effect.provide(
          harness("sqlite", () =>
            Deferred.succeed(started, undefined).pipe(
              Effect.andThen(Effect.never),
              Effect.ensuring(
                Effect.sync(() => {
                  finalized = true;
                }),
              ),
            ),
          ),
        ),
      );
    }
  }),
);

it.effect(
  "Effect's MCP HTTP transport receives an isolated authenticated principal on each tool call",
  () =>
    Effect.gen(function* () {
      const alice = yield* issue("alice");
      const bob = yield* issue("bob");

      const toolkit = Toolkit.make(
        Tool.make("whoami", { success: Schema.String, failure: OAuthServer.InvalidToken }),
      );

      const tools = McpServer.toolkit(toolkit).pipe(
        Layer.provide(
          toolkit.toLayer({
            whoami: () =>
              Effect.gen(function* () {
                const access = yield* OAuthServer.CurrentAccess;

                if (access === undefined) return yield* OAuthServer.InvalidToken.make({});

                return access.subjectId;
              }),
          }),
        ),
        Layer.provide(
          McpServer.layerHttp({
            name: "test",
            version: "1",
            path: "/mcp",
            protocols: [McpProtocol.v2026_07_28],
          }),
        ),
        Layer.provide(server.middleware(["read"]).layer),
      );

      const routes = Layer.mergeAll(tools, server.routes).pipe(
        Layer.provide(Layer.succeed(server.Service, alice.service)),
        Layer.provideMerge(Layer.succeed(Clock.Clock, yield* Clock.Clock)),
      );

      yield* Effect.acquireUseRelease(
        Effect.sync(() => HttpRouter.toWebHandler(routes, { disableLogger: true })),
        ({ handler }) =>
          Effect.gen(function* () {
            const send = (token?: string) =>
              Effect.promise(() =>
                handler(
                  new Request(resource, {
                    method: "POST",
                    headers: {
                      "content-type": "application/json",
                      accept: "application/json, text/event-stream",
                      "MCP-Protocol-Version": "2026-07-28",
                      "Mcp-Method": "tools/call",
                      "Mcp-Name": "whoami",
                      ...(token ? { authorization: `Bearer ${token}` } : {}),
                    },
                    body: JSON.stringify({
                      jsonrpc: "2.0",
                      id: 1,
                      method: "tools/call",
                      params: {
                        name: "whoami",
                        arguments: {},
                        _meta: {
                          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {},
                        },
                      },
                    }),
                  }),
                ),
              );

            const anonymous = yield* send();

            expect(anonymous.status).toBe(401);
            expect(anonymous.headers.get("www-authenticate")).toContain(
              "/.well-known/oauth-protected-resource/mcp",
            );
            for (const [token, user] of [
              [alice.tokens.access_token, "alice"],
              [bob.tokens.access_token, "bob"],
              [alice.tokens.access_token, "alice"],
            ]) {
              const response = yield* send(token);

              expect(response.status).toBe(200);

              const json = yield* body(
                response,
                Schema.Struct({
                  result: Schema.Struct({
                    content: Schema.Array(Schema.Struct({ text: Schema.String })),
                  }),
                }),
              );

              expect(json.result.content[0].text).toBe(JSON.stringify(user));
            }
            expect((yield* send(alice.tokens.refresh_token)).status).toBe(401);
            const writeOnly = yield* issue("alice", "write");

            expect((yield* send(writeOnly.tokens.access_token)).status).toBe(403);
            yield* TestClock.adjust("11 minutes");
            expect((yield* send(alice.tokens.access_token)).status).toBe(401);
          }),
        ({ dispose }) => Effect.promise(dispose),
      );
    }).pipe(Effect.provide(harness())),
);
