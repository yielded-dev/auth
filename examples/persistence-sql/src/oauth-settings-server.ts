import { BunHttpServer, BunRuntime, BunServices } from "@effect/platform-bun";
import { Config, Effect, FileSystem, Layer, Option, Path } from "effect";
import { HttpMiddleware, HttpRouter, HttpServerResponse } from "effect/http";

import { CryptoLive } from "../../shared/crypto";
import { DatabaseLive } from "./data";
import { settingsApplication } from "./oauth-settings-application";
import { SettingsKeysLive } from "./oauth-settings-keys";
import { YieldedKeys } from "./yielded-keys";

const server = Layer.unwrap(
  Effect.gen(function* () {
    const port = yield* Config.Port("AUTH_PORT").pipe(Config.withDefault(4185));

    const origin = yield* Config.URL("AUTH_ORIGIN").pipe(
      Config.withDefault(new URL(`http://localhost:${port}`)),
    );

    const clientId = yield* Config.String("GITHUB_CLIENT_ID");
    const clientSecret = yield* Config.Redacted("GITHUB_CLIENT_SECRET");
    const externalSubject = yield* Config.String("GITHUB_USER_ID");

    const displayName = yield* Config.String("YIELDED_DISPLAY_NAME").pipe(
      Config.withDefault("Yielded member"),
    );

    const agentSecret = yield* Config.Redacted("YIELDED_AGENT_CLIENT_SECRET").pipe(Config.option);

    const agentOrigin = yield* Config.URL("YIELDED_AGENT_ORIGIN").pipe(
      Config.withDefault(new URL("https://agent.yielded.dev")),
    );

    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const root = new URL("../dist/", import.meta.url).pathname;
    const html = yield* fs.readFileString(path.join(root, "oauth-settings.html"));
    const assets = yield* fs.readDirectory(path.join(root, "assets"));
    const stylesheet = assets.find((name) => name.startsWith("style-") && name.endsWith(".css"));

    if (stylesheet === undefined)
      return yield* Effect.die(new Error("Build the browser assets before starting Auth"));

    const page = HttpServerResponse.text(html, {
      contentType: "text/html",
      headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" },
    });

    const agent = Option.isNone(agentSecret)
      ? undefined
      : {
          origin: agentOrigin,
          secret: agentSecret.value,
          keys: yield* YieldedKeys.pipe(Effect.provide(YieldedKeys.layer)),
        };

    const application = settingsApplication({
      origin,
      clientId,
      clientSecret,
      externalSubject,
      displayName,
      stylesheet: `/assets/${stylesheet}`,
      ...(agent === undefined ? {} : { agent }),
    }).pipe(Layer.provide(DatabaseLive), Layer.provide(SettingsKeysLive));

    const routes = Layer.mergeAll(
      application,
      HttpRouter.add("GET", "/", HttpServerResponse.redirect("/oauth-settings")),
      ...(["/oauth-settings", "/oauth-settings/callback", "/sign-in"] as const).map((route) =>
        HttpRouter.add("GET", route, page),
      ),
      ...(["ink", "paper"] as const).map((mode) =>
        HttpRouter.add(
          "GET",
          `/brand/auth-${mode}.svg`,
          HttpServerResponse.file(
            new URL(`../../../.github/assets/lockup-auth-${mode}.svg`, import.meta.url).pathname,
          ),
        ),
      ),
      HttpRouter.addAll(
        assets.map((name) =>
          HttpRouter.route(
            "GET",
            `/assets/${name}`,
            HttpServerResponse.file(path.join(root, "assets", name)),
          ),
        ),
      ),
    );

    return HttpRouter.serve(routes, { disableLogger: true }).pipe(
      Layer.provide(BunHttpServer.layer({ hostname: "127.0.0.1", port })),
      Layer.provide(Layer.succeed(HttpMiddleware.TracerDisabledWhen, () => true)),
    );
  }),
).pipe(Layer.provide(CryptoLive), Layer.provide(BunServices.layer));

if (import.meta.main) BunRuntime.runMain(Layer.launch(server));
