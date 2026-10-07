import { OAuth, Strava } from "@yielded/auth";
import { Effect, Layer, Redacted, Schema } from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";

import { DemoHttpLive } from "./oauth-demo-provider";

export const providerLayer = (options: {
  readonly origin: URL;
  readonly demo: boolean;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
}) =>
  Layer.effect(
    OAuth.OAuthProtocol,
    Effect.gen(function* () {
      const configure = Strava.provider({
        clientId: options.clientId,
        clientSecret: options.clientSecret,
      }).configure({
        provider: OAuth.OAuthProviderKey.make("strava"),
        callbacks: [
          {
            callbackId: OAuth.OAuthCallbackId.make("strava"),
            redirectUri: OAuth.OAuthRedirectUri.make(
              `${options.origin.origin}/oauth-settings/callback`,
            ),
          },
        ],
      });

      const protocol = yield* options.demo
        ? configure.pipe(Effect.provide(DemoHttpLive))
        : configure;

      return options.demo
        ? ({
            ...protocol,
            prepareAuthorization: (input) =>
              protocol.prepareAuthorization(input).pipe(
                Effect.map((prepared) => {
                  const remote = new URL(Redacted.value(prepared.authorizationUrl));
                  const local = new URL("/demo/authorize", options.origin);

                  local.search = remote.search;

                  return { ...prepared, authorizationUrl: Redacted.make(local.href) };
                }),
              ),
          } satisfies OAuth.OAuthProtocol["Service"])
        : protocol;
    }),
  );

const AuthorizationQuery = Schema.Struct({
  state: Schema.NonEmptyString,
  redirect_uri: Schema.String,
});

const escape = (value: string) =>
  value.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;");

/** This page only exists in explicit localhost demo mode. Provider HTTP is simulated;
 * the real Strava protocol, private request binding and SQL workflow still run. */
export const demoRoutes = (origin: URL) =>
  HttpRouter.add(
    "GET",
    "/demo/authorize",
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;

      const query = yield* Schema.decodeUnknownEffect(AuthorizationQuery)(
        Object.fromEntries(new URL(request.url, origin).searchParams),
      );

      if (query.redirect_uri !== `${origin.origin}/oauth-settings/callback`)
        return HttpServerResponse.empty({ status: 400 });

      const callback = (code?: string) => {
        const url = new URL(query.redirect_uri);

        url.searchParams.set("state", query.state);
        if (code === undefined) url.searchParams.set("error", "access_denied");
        else {
          url.searchParams.set("code", code);
          url.searchParams.set("scope", "read");
        }

        return escape(url.href);
      };

      return HttpServerResponse.text(
        `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Simulated Strava consent</title></head><body><h1>Simulated Strava consent</h1><p>Local demonstration only. Choose a demo identity; no real provider is contacted.</p><ul><li><a href="${callback("123")}">Continue as Demo 123 — initial identity</a></li><li><a href="${callback("456")}">Continue as Demo 456 — available to link</a></li><li><a href="${callback("789")}">Continue as Demo 789 — another account</a></li></ul><a href="${callback()}">Cancel consent</a></body></html>`,
        {
          contentType: "text/html",
          headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" },
        },
      );
    }).pipe(
      Effect.catchTag("SchemaError", () =>
        Effect.succeed(HttpServerResponse.empty({ status: 400 })),
      ),
    ),
  );
