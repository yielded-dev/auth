import * as SqliteClient from "@effect/sql-sqlite-do/SqliteClient";
import { Effect, Layer, Schema } from "effect";
import { HttpMiddleware, HttpRouter, HttpServer } from "effect/http";

import { CryptoLive } from "../../shared/crypto";
import { settingsApplication } from "./oauth-settings-application";
import { SettingsKeyMaterial, settingsKeysLayer } from "./oauth-settings-keys";
import { IdentityKeyMaterial } from "./yielded-keys";

const Origin = Schema.String.check(
  Schema.makeFilter((value) => {
    try {
      const url = new URL(value);

      return url.protocol === "https:" && url.origin === value;
    } catch {
      return false;
    }
  }),
);

const Configuration = Schema.Struct({
  AUTH_ORIGIN: Origin,
  GITHUB_CLIENT_ID: Schema.NonEmptyString,
  GITHUB_CLIENT_SECRET: Schema.RedactedFromValue(Schema.NonEmptyString),
  GITHUB_USER_ID: Schema.String.check(Schema.isPattern(/^[0-9]{1,20}$/)),
  YIELDED_DISPLAY_NAME: Schema.NonEmptyString.check(Schema.isMaxLength(256)),
  YIELDED_AGENT_ORIGIN: Origin,
  YIELDED_AGENT_CLIENT_SECRET: Schema.RedactedFromValue(Schema.NonEmptyString),
  AUTH_SETTINGS_KEYS: SettingsKeyMaterial,
  AUTH_IDENTITY_KEYS: IdentityKeyMaterial,
});

type Environment = typeof Configuration.Encoded & {
  readonly ASSETS: Fetcher;
  readonly AUTH: DurableObjectNamespace;
};

class HostedAuthUnavailable extends Schema.TaggedError<HostedAuthUnavailable>()(
  "HostedAuthUnavailable",
  {},
) {}

/** One SQL transaction owner for login identities, session validity and grants.
 * Keep the binding, class and instance name unchanged across deployments.
 */
export class HostedAuth {
  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Environment,
  ) {}

  fetch(request: Request): Promise<Response> {
    return Effect.runPromise(
      Effect.gen({ self: this }, function* () {
        const config = yield* Schema.decodeEffect(Configuration)(this.env, {
          reportInput: false,
        });

        const response = yield* Effect.tryPromise({
          try: () => this.env.ASSETS.fetch(`${config.AUTH_ORIGIN}/oauth-settings.html`),
          catch: () => HostedAuthUnavailable.make({}),
        });

        if (response.status !== 200) return yield* HostedAuthUnavailable.make({});

        const html = yield* Effect.tryPromise({
          try: () => response.text(),
          catch: () => HostedAuthUnavailable.make({}),
        });

        const stylesheet = html.match(
          /<link rel="stylesheet"[^>]*href="(\/assets\/[^"<>]+\.css)"/,
        )?.[1];

        if (stylesheet === undefined) return yield* HostedAuthUnavailable.make({});

        const application = settingsApplication({
          origin: new URL(config.AUTH_ORIGIN),
          clientId: config.GITHUB_CLIENT_ID,
          clientSecret: config.GITHUB_CLIENT_SECRET,
          externalSubject: config.GITHUB_USER_ID,
          displayName: config.YIELDED_DISPLAY_NAME,
          stylesheet,
          agent: {
            origin: new URL(config.YIELDED_AGENT_ORIGIN),
            secret: config.YIELDED_AGENT_CLIENT_SECRET,
            keys: config.AUTH_IDENTITY_KEYS,
          },
        }).pipe(
          Layer.provide(settingsKeysLayer(config.AUTH_SETTINGS_KEYS)),
          Layer.provide(SqliteClient.layer({ storage: this.state.storage })),
          Layer.provide(CryptoLive),
          Layer.provide(HttpServer.layerServices),
          Layer.provide(Layer.succeed(HttpMiddleware.TracerDisabledWhen, () => true)),
        );

        const web = yield* Effect.acquireRelease(
          Effect.sync(() => HttpRouter.toWebHandler(application, { disableLogger: true })),
          (web) => Effect.promise(() => web.dispose()),
        );

        const result = yield* Effect.tryPromise({
          try: () => web.handler(request),
          catch: () => HostedAuthUnavailable.make({}),
        });

        const body = yield* Effect.tryPromise({
          try: () => result.arrayBuffer(),
          catch: () => HostedAuthUnavailable.make({}),
        });

        return new Response(body, { status: result.status, headers: result.headers });
      }).pipe(
        Effect.scoped,
        Effect.catch(() =>
          Effect.succeed(
            new Response("Sign-in is temporarily unavailable. Start a new attempt later.", {
              status: 503,
              headers: { "cache-control": "no-store" },
            }),
          ),
        ),
      ),
    );
  }
}

export default {
  async fetch(request: Request, env: Environment): Promise<Response> {
    const url = new URL(request.url);

    if (url.origin !== env.AUTH_ORIGIN) return new Response("Not found", { status: 404 });
    if (url.pathname === "/") return Response.redirect(`${url.origin}/oauth-settings`, 303);
    if (["/oauth-settings", "/oauth-settings/callback", "/sign-in"].includes(url.pathname)) {
      if (request.method !== "GET") return new Response(null, { status: 405 });
      // Static asset lookups never carry provider callback parameters.
      const page = await env.ASSETS.fetch(`${url.origin}/oauth-settings.html`);
      const headers = new Headers(page.headers);

      headers.set("cache-control", "no-store");
      headers.set("referrer-policy", "no-referrer");

      return new Response(page.body, { status: page.status, headers });
    }
    if (url.pathname.startsWith("/assets/") || url.pathname.startsWith("/brand/"))
      return env.ASSETS.fetch(request);

    return env.AUTH.getByName("yielded-auth-v1").fetch(request);
  },
};
