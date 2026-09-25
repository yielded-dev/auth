import { BunHttpServer, BunRuntime } from "@effect/platform-bun";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import * as GitHub from "@yielded/auth-openid-client/GitHub";
import { OAuthAppPersistence } from "@yielded/auth-persistence";
import { OAuthRejected } from "@yielded/auth/OAuth";
import * as OAuthApp from "@yielded/auth/OAuthApp";
import { SubjectId } from "@yielded/auth/Schema";
import { Config, Effect, Layer, Redacted, Schema } from "effect";
import {
  HttpMiddleware,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { SqlClient } from "effect/unstable/sql";

const app = OAuthApp.make("github", {
  claims: Schema.Struct({ role: Schema.Literal("owner") }),
  returnTargets: ["/account"],
});

const runtime = Layer.unwrap(
  Effect.gen(function* () {
    const origin = yield* Config.String("APP_ORIGIN").pipe(
      Config.withDefault("http://localhost:3000"),
    );

    const clientId = yield* Config.String("GITHUB_CLIENT_ID");
    const clientSecret = yield* Config.Redacted("GITHUB_CLIENT_SECRET");
    const githubUserId = yield* Config.String("GITHUB_USER_ID");
    const sessionKey = yield* Config.Redacted("SESSION_KEY");
    const transactionKey = yield* Config.Redacted("OAUTH_TRANSACTION_KEY");
    const tokenKey = yield* Config.Redacted("OAUTH_TOKEN_KEY");

    const keyring = (material: Redacted.Redacted<string>) => ({
      activeKeyId: "v1",
      keys: [{ id: "v1", material }],
    });

    const database = SqliteClient.layer({ filename: "github-auth.sqlite" });

    // This runnable example owns its file/schema. Production applications apply
    // OAuthAppPersistence.migration once through their normal migration system.
    const migrated = Layer.effectDiscard(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;

        yield* sql.unsafe(
          OAuthAppPersistence.migration.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS"),
        );
      }),
    ).pipe(Layer.provideMerge(database));

    const accounts = Layer.succeed(app.Accounts, {
      resolve: Effect.fn("GitHubApp.resolveAccount")(function* (verified) {
        if (verified.identity.subject !== githubUserId) return yield* OAuthRejected.make({});

        return {
          subjectId: SubjectId.make(`github:${githubUserId}`),
          claims: { role: "owner" as const },
        };
      }),
    });

    const live = app
      .layer({
        origin,
        sessionKeys: keyring(sessionKey),
        transactionKeys: keyring(transactionKey),
        tokenKeys: keyring(tokenKey),
        provider: GitHub.appProvider({ clientId, clientSecret }),
      })
      .pipe(
        Layer.provide(accounts),
        Layer.provide(OAuthAppPersistence.layer.pipe(Layer.provide(migrated))),
      );

    const home = HttpRouter.add(
      "GET",
      "/",
      HttpServerResponse.html(`<a href="${app.paths.signIn}">Sign in with GitHub</a>`),
    );

    const account = Layer.unwrap(
      Effect.gen(function* () {
        const sessions = yield* app.Sessions;

        return HttpRouter.add(
          "GET",
          "/account",
          Effect.gen(function* () {
            const request = yield* HttpServerRequest.HttpServerRequest;
            const credential = request.cookies[app.cookieName];

            if (credential === undefined) return HttpServerResponse.redirect(app.paths.signIn);
            const session = yield* sessions.verify(Redacted.make(credential));

            return yield* HttpServerResponse.json(session);
          }).pipe(
            Effect.catch(() => Effect.succeed(HttpServerResponse.redirect(app.paths.signIn))),
          ),
        );
      }),
    );

    return Layer.mergeAll(app.routes, home, account).pipe(Layer.provide(live));
  }),
);

HttpRouter.serve(runtime).pipe(
  Layer.provide(BunHttpServer.layer({ port: 3000 })),
  // Server tracing otherwise records callback query strings containing codes.
  Layer.provide(
    Layer.succeed(
      HttpMiddleware.TracerDisabledWhen,
      (request) => new URL(request.url, "http://localhost").pathname === app.paths.callback,
    ),
  ),
  Layer.launch,
  BunRuntime.runMain,
);
