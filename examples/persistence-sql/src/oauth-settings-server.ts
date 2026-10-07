import { BunHttpServer, BunRuntime, BunServices } from "@effect/platform-bun";
import { Hooks, Http, OAuth } from "@yielded/auth";
import { Config, Effect, FileSystem, Layer, Path, Redacted } from "effect";
import { FetchHttpClient, HttpRouter, HttpServerResponse } from "effect/http";

import { CryptoLive } from "../../shared/crypto";
import { DatabaseLive } from "./data";
import { SettingsActionsLive, SettingsAuth } from "./oauth-settings-auth";
import { SettingsKeysLive } from "./oauth-settings-keys";
import { demoRoutes, providerLayer } from "./oauth-settings-provider";
import { settingsStorage } from "./oauth-settings-storage";

const server = Layer.unwrap(
  Effect.gen(function* () {
    const port = yield* Config.Port("AUTH_PORT").pipe(Config.withDefault(4185));

    const origin = yield* Config.URL("AUTH_ORIGIN").pipe(
      Config.withDefault(new URL(`http://localhost:${port}`)),
    );

    const demo = yield* Config.Boolean("OAUTH_DEMO").pipe(Config.withDefault(false));

    if (demo && (origin.protocol !== "http:" || origin.hostname !== "localhost"))
      return yield* OAuth.OAuthConfigurationError.make({ reason: "policy" });
    const clientId = demo ? "1234" : yield* Config.String("STRAVA_CLIENT_ID");

    const clientSecret = demo
      ? Redacted.make("public-demo-client-secret")
      : yield* Config.Redacted("STRAVA_CLIENT_SECRET");

    const externalSubject = demo ? "123" : yield* Config.String("STRAVA_ATHLETE_ID");

    const http = Http.make(SettingsAuth, {
      origin: origin.origin,
      cookie: { prefix: "oauth-settings-", secure: origin.protocol === "https:" },
    });

    const infrastructure = Layer.mergeAll(
      DatabaseLive,
      SettingsKeysLive,
      Hooks.LifecycleHooks.empty,
      providerLayer({ origin, demo, clientId, clientSecret }),
      OAuth.OAuthReturnTargets.exactRoutes(["/oauth-settings"]),
      Layer.succeed(SettingsAuth.strategies.oauth.SessionClaims, {
        resolve: () => Effect.succeed({ displayName: "SQL example member" }),
      }),
    ).pipe(Layer.provideMerge(CryptoLive), Layer.provideMerge(FetchHttpClient.layer));

    const storage = settingsStorage(externalSubject, demo).pipe(Layer.provideMerge(infrastructure));

    const live = SettingsAuth.layer.pipe(
      Layer.provide(SettingsActionsLive.pipe(Layer.provideMerge(storage))),
    );

    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const root = new URL("../dist/", import.meta.url).pathname;

    const html = (yield* fs.readFileString(path.join(root, "oauth-settings.html"))).replace(
      "__OAUTH_DEMO__",
      String(demo),
    );

    const page = HttpServerResponse.text(html, {
      contentType: "text/html",
      headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" },
    });

    const assets = yield* fs.readDirectory(path.join(root, "assets"));

    const routes = Layer.mergeAll(
      http.routes(),
      HttpRouter.add("GET", "/", HttpServerResponse.redirect("/oauth-settings")),
      HttpRouter.add("GET", "/oauth-settings", page),
      HttpRouter.add("GET", "/oauth-settings/callback", page),
      HttpRouter.addAll(
        assets.map((name) =>
          HttpRouter.route(
            "GET",
            `/assets/${name}`,
            HttpServerResponse.file(path.join(root, "assets", name)),
          ),
        ),
      ),
      demo ? demoRoutes(origin) : Layer.empty,
    ).pipe(Layer.provide(live));

    return HttpRouter.serve(routes, { disableLogger: true }).pipe(
      Layer.provide(BunHttpServer.layer({ hostname: "127.0.0.1", port })),
    );
  }),
).pipe(Layer.provide(BunServices.layer));

if (import.meta.main) BunRuntime.runMain(Layer.launch(server));
