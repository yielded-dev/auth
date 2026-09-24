import { BunHttpServer, BunRuntime } from "@effect/platform-bun";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { OAuthAppPersistence, OAuthServerPersistence } from "@yielded/auth-persistence";
import { OAuthRejected } from "@yielded/auth/OAuth";
import * as OAuthApp from "@yielded/auth/OAuthApp";
import * as OAuthServer from "@yielded/auth/OAuthServer";
import { SubjectId } from "@yielded/auth/Schema";
import * as Strava from "@yielded/auth/Strava";
import { Config, Effect, Layer, Redacted, Schema } from "effect";
import { McpProtocol, McpServer, Tool, Toolkit } from "effect/unstable/ai";
import {
  FetchHttpClient,
  HttpMiddleware,
  HttpRouter,
  HttpServerRequest,
} from "effect/unstable/http";
import { SqlClient } from "effect/unstable/sql";

const oauth = OAuthServer.make("mcp", { scopes: ["athlete:read"] });

const app = OAuthApp.make("strava", {
  claims: Schema.Struct({}),
  returnTargets: [oauth.paths.authorize],
});

const toolkit = Toolkit.make(
  Tool.make("connected_athlete", {
    description: "Identify the athlete who authorized this MCP client.",
    success: Schema.Struct({ subjectId: Schema.String }),
    failure: OAuthServer.InvalidToken,
  }),
);

const handlers = toolkit.toLayer({
  connected_athlete: Effect.fn("StravaMcp.connectedAthlete")(function* () {
    const access = yield* OAuthServer.CurrentAccess;

    if (access === undefined) return yield* OAuthServer.InvalidToken.make({});

    // Applications resolve this subject's permitted connection from trusted storage
    // before calling the app service's withAccessToken. Never take a grant ID from tool input.
    return { subjectId: access.subjectId };
  }),
});

const runtime = Layer.unwrap(
  Effect.gen(function* () {
    const origin = yield* Config.String("APP_ORIGIN").pipe(
      Config.withDefault("http://localhost:3000"),
    );

    const clientId = yield* Config.String("STRAVA_CLIENT_ID");
    const clientSecret = yield* Config.Redacted("STRAVA_CLIENT_SECRET");
    const athleteId = yield* Config.String("STRAVA_ATHLETE_ID");
    const sessionKey = yield* Config.Redacted("SESSION_KEY");
    const transactionKey = yield* Config.Redacted("OAUTH_TRANSACTION_KEY");
    const tokenKey = yield* Config.Redacted("OAUTH_TOKEN_KEY");
    const issuerKey = yield* Config.Redacted("MCP_SIGNING_KEY");
    const mcpClientId = yield* Config.String("MCP_CLIENT_ID");
    const mcpRedirectUri = yield* Config.String("MCP_REDIRECT_URI");

    const keyring = (material: Redacted.Redacted<string>) => ({
      activeKeyId: "v1",
      keys: [{ id: "v1", material }],
    });

    const database = Layer.effectDiscard(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;

        // The example owns this file. Production applications apply each migration once.
        for (const migration of [OAuthAppPersistence.migration, OAuthServerPersistence.migration]) {
          yield* sql.unsafe(migration.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS"));
        }
      }),
    ).pipe(Layer.provideMerge(SqliteClient.layer({ filename: "strava-mcp.sqlite" })));

    const login = app
      .layer({
        origin,
        sessionKeys: keyring(sessionKey),
        transactionKeys: keyring(transactionKey),
        tokenKeys: keyring(tokenKey),
        provider: Strava.provider({ clientId, clientSecret, scopes: ["activity:read_all"] }),
      })
      .pipe(
        Layer.provide(
          Layer.succeed(app.Accounts, {
            resolve: ({ identity }) =>
              identity.subject === athleteId
                ? Effect.succeed({ subjectId: SubjectId.make(`strava:${athleteId}`), claims: {} })
                : Effect.fail(OAuthRejected.make({})),
          }),
        ),
        Layer.provide(OAuthAppPersistence.layer.pipe(Layer.provide(database))),
        Layer.provide(FetchHttpClient.layer),
      );

    const identity = Layer.effect(
      oauth.Identity,
      Effect.gen(function* () {
        const sessions = yield* app.Sessions;

        return oauth.Identity.of({
          current: Effect.gen(function* () {
            const request = yield* HttpServerRequest.HttpServerRequest;
            const cookie = request.cookies[app.cookieName];

            if (cookie === undefined) return undefined;

            return yield* sessions.verify(Redacted.make(cookie)).pipe(
              Effect.map((session) => session.subjectId),
              Effect.catchTag("SessionInvalid", () => Effect.succeed(undefined)),
              Effect.mapError(() => OAuthServer.Unavailable.make({})),
            );
          }),
        });
      }),
    ).pipe(Layer.provide(login));

    const authorization = oauth
      .layer({
        origin,
        resource: `${origin}/mcp`,
        loginPath: app.paths.signIn,
        keys: keyring(issuerKey),
        clients: [{ clientId: mcpClientId, name: "My MCP client", redirectUris: [mcpRedirectUri] }],
      })
      .pipe(
        Layer.provide(identity),
        Layer.provide(OAuthServerPersistence.layer.pipe(Layer.provide(database))),
      );

    const mcp = McpServer.toolkit(toolkit).pipe(
      Layer.provide(handlers),
      Layer.provide(
        McpServer.layerHttp({
          name: "Strava",
          version: "1.0.0",
          path: "/mcp",
          protocols: [McpProtocol.v2026_07_28, McpProtocol.v2025_11_25],
          allowedOrigins: [new URL(mcpRedirectUri).origin],
        }),
      ),
      Layer.provide(oauth.middleware(["athlete:read"]).layer),
    );

    return Layer.mergeAll(mcp, oauth.routes, app.routes.pipe(Layer.provide(login))).pipe(
      Layer.provide(authorization),
      Layer.provide(
        HttpRouter.middleware(
          HttpMiddleware.cors({
            allowedOrigins: [new URL(mcpRedirectUri).origin],
            allowedMethods: ["GET", "POST", "OPTIONS"],
            exposedHeaders: ["WWW-Authenticate", "Mcp-Session-Id"],
          }),
        ).layer,
      ),
    );
  }),
);

// OAuth requests/responses contain credentials. Keep their URLs out of access logs/traces.
HttpRouter.serve(runtime, { disableLogger: true }).pipe(
  Layer.provide(BunHttpServer.layer({ port: 3000 })),
  Layer.provide(Layer.succeed(HttpMiddleware.TracerDisabledWhen, () => true)),
  Layer.launch,
  BunRuntime.runMain,
);
