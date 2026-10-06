import { Auth, Http, OAuth, Sessions, Slack } from "@yielded/auth";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import { Effect, FileSystem, Layer } from "effect";
import { FetchHttpClient, HttpRouter, HttpServerResponse } from "effect/http";

import { CryptoLive } from "../../shared/crypto";
import { OAuthSignInApi } from "./oauth-contract";
import { makeStorage } from "./oauth-storage";

/** Single-owner sign-in example. SQL owns the exact external identity tuple;
 * verified workspace membership is checked separately before session issuance. */
export const makeSlackExample = (config: {
  readonly origin: string;
  readonly clientId: string;
  readonly clientSecret: Slack.ProviderRegistration["clientSecret"];
  readonly userId: string;
  readonly teamId: string;
  readonly filename: string;
  readonly sessionKeys: Sessions.SessionSigningKeyring;
  readonly transactionKeys: Sessions.SessionSigningKeyring;
}) => {
  const AppAuth = Auth.make(OAuthSignInApi, {
    sessions: Sessions.stateless({ keys: config.sessionKeys }),
    strategies: { oauth: OAuth.make({ profiles: { slack: Slack.SlackUserProfile } }) },
    defaultStrategy: "oauth",
  });

  const http = Http.make(AppAuth, {
    origin: config.origin,
    cookie: { secure: new URL(config.origin).protocol === "https:" },
    oauth: {
      providers: {
        slack: Slack.provider({
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          scopes: ["openid", "profile", "email"],
          team: config.teamId,
        }),
      },
    },
  });

  const dependencies = Layer.mergeAll(
    makeStorage({
      moduleId: "example/oauth/oauth",
      provider: "slack",
      issuer: "https://slack.com",
      externalSubject: config.userId,
      subjectId: `slack:${config.userId}`,
      filename: config.filename,
    }),
    Layer.succeed(AppAuth.strategies.oauth.SessionClaims, {
      resolve: Effect.fnUntraced(function* ({ identity }) {
        if (identity.profile?.providerData?.["https://slack.com/team_id"] !== config.teamId)
          return yield* OAuth.OAuthUnavailable.make({});

        return { role: "owner" as const };
      }),
    }),
    Auth.RequestBindingConfig.layer({
      generation: 1,
      lifetimeMillis: 600_000,
      keyring: config.transactionKeys,
    }),
    OAuth.OAuthTransactionProtector.layer(config.transactionKeys),
    OAuth.OAuthReturnTargets.exactRoutes(["/account"]),
    FetchHttpClient.layer,
  ).pipe(Layer.provideMerge(CryptoLive), Layer.provideMerge(LifecycleHooks.empty));

  const browser = Layer.unwrap(
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;

      const javascript = yield* fs.readFileString(
        new URL("../dist/oauth-client.js", import.meta.url).pathname,
      );

      return HttpRouter.add(
        "GET",
        "/oauth-client.js",
        HttpServerResponse.text(javascript, { contentType: "text/javascript" }),
      );
    }),
  );

  const login = HttpRouter.add(
    "GET",
    "/login",
    HttpServerResponse.html(`<!doctype html>
    <html lang="en"><meta charset="utf-8"><title>Sign in with Slack</title>
    <body data-provider="slack" data-return-target="/account">
    <h1>Sign in with Slack</h1><p>Use the configured Slack account and workspace.</p>
    <button aria-label="Sign in with Slack"><img alt="Sign in with Slack"
      src="https://platform.slack-edge.com/img/sign_in_with_slack.png" width="170" height="40"></button>
    <output aria-live="polite"></output><script type="module" src="/oauth-client.js"></script></body></html>`),
  );

  const account = HttpRouter.add(
    "GET",
    "/account",
    Effect.gen(function* () {
      const auth = yield* AppAuth;
      const session = yield* auth.getSession();

      if (session === null) return HttpServerResponse.redirect("/login");

      return yield* HttpServerResponse.json({
        subjectId: session.subjectId,
        role: session.claims.role,
      });
    }),
  ).pipe(http.middleware);

  return Layer.mergeAll(
    http.routes(),
    browser,
    login,
    account,
    HttpRouter.add("GET", "/", HttpServerResponse.redirect("/login")),
  ).pipe(Layer.provide(http.layer), Layer.provide(dependencies));
};
