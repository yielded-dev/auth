---
title: Slack
description: Set up Sign in with Slack using the shared OIDC flow.
---

`Slack.provider` adds Sign in with Slack to an [OAuth strategy](./oauth).
It verifies an ID token and establishes your application's session. The preset
does not retain Slack API access or install a bot.

## Configure your Slack app

Create an app in [Slack app management](https://api.slack.com/apps).
Under **OAuth & Permissions**, register your exact HTTPS callback,
`https://app.example.com/auth/slack/callback`, and add the user scopes `openid`,
`profile`, and `email`. Find the client ID and client secret under **Basic Information**.
Keep Sign in with Slack scopes separate from bot and other Web API scopes;
Slack requires separate authorization flows for those permissions.
See [Slack's setup guide](https://docs.slack.dev/authentication/sign-in-with-slack/).

Load the credentials while building the server Layer:

```ts title="apps/server/slack.ts"
import { Config, Effect, Layer } from "effect";
import { Http, Slack } from "@yielded/auth";

import { AppAuth } from "./auth";

export const AuthRoutes = Layer.unwrap(
  Effect.gen(function* () {
    return Http.layer(AppAuth, {
      origin: yield* Config.String("APP_ORIGIN"),
      oauth: {
        providers: {
          slack: Slack.provider({
            clientId: yield* Config.String("SLACK_CLIENT_ID"),
            clientSecret: yield* Config.Redacted("SLACK_CLIENT_SECRET"),
            scopes: ["openid", "profile", "email"],
          }),
        },
      },
    });
  }),
);
```

[Supply HTTP, crypto, persistence and application services](../reference/oauth#supply-the-services)
to this Layer. Keep it alive for the server's lifetime. The default scope is
`openid`; request `profile` and `email` only when your application needs them.
Start with `auth.signIn({ provider: "slack", returnTarget: "/account" })` and
redirect to the returned authorization URL. The callback completes sign-in.

## Identity and workspace policy

The durable identity is `(provider key, "https://slack.com", verified sub)`.
Keep `sub` unchanged; neither the email address nor workspace name identifies a
local account. Never link accounts merely because profile emails match, even when
`email_verified` is true.

The preset carries `SlackUserProfile` through ID-token projection. Declare the
same schema on the strategy to get typed `providerData` in
`SessionClaims.resolve`:

```ts
const social = OAuth.make({ profiles: { slack: Slack.SlackUserProfile } });
```

The library validates the schema before calling your resolver, which can read
`identity.profile?.providerData?.["https://slack.com/team_id"]` as
`string | undefined` without decoding it again. The schema contains standard OIDC
profile fields and the optional
`https://slack.com/team_id` and `https://slack.com/user_id` claims from the verified
ID token. Fields absent from that token stay absent; no UserInfo request is made.

The optional `team` provider option hints which workspace to use on Slack's consent
screen. It does **not** restrict membership. Applications requiring a workspace
must compare the verified `team_id` against their own policy and reject missing or
different values before issuing a session. The runnable example does this.

## Run the example

The [Slack application](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/slack-app.ts)
uses the shared Atom browser client, SQL identity storage, and stateless sessions.
It provisions one explicitly configured Slack user and rejects other identities.

1. Forward an HTTPS development origin to `127.0.0.1:3000`. Set `APP_ORIGIN` to that
   public origin and register its `/auth/slack/callback` URL in the Slack app.
2. Set `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `SLACK_USER_ID` (the Slack member ID,
   used as the expected `sub`), and `SLACK_TEAM_ID` (workspace ID).
3. Set `SESSION_KEY` and `OAUTH_TRANSACTION_KEY` to distinct base64url encodings of
   32 random bytes. For example, run `openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'`
   separately for each key. Preserve these keys across restarts.
4. Run `vp run @yielded/example-auth#example:slack` from the repository root and open
   `APP_ORIGIN/login`. Sign in with the configured Slack account and workspace.
5. After the callback, `/account` returns the local `subjectId` and `role: "owner"`.
   A different subject or workspace must not receive a session.

The example stores development state in `examples/auth/slack-auth.sqlite`. To
start over, stop the example, remove only that database and its SQLite sidecar
files, and clear cookies for the development origin. This resets this example's
account link and flows. No provider grant is retained, so `OAUTH_TOKEN_KEY` is
not needed.

## Protocol profile

The preset uses Slack's [discovery document](https://slack.com/.well-known/openid-configuration)
with these constraints:

| Concern                  | Behavior                                                                                      |
| ------------------------ | --------------------------------------------------------------------------------------------- |
| Issuer                   | Exact `https://slack.com`                                                                     |
| Authorization / callback | `/openid/connect/authorize`, authorization code, query response                               |
| Token exchange           | `/api/openid.connect.token`, `client_secret_basic`                                            |
| Signature                | Advertised RS256, keys at `/openid/connect/keys`; issuer, audience, expiry and nonce verified |
| PKCE                     | S256 challenge and captured verifier on every exchange                                        |
| Response issuer          | Slack does not advertise RFC 9207 `iss`; use a distinct callback URL                          |
| Access                   | Sign-in only; no retained access, refresh, revocation or UserInfo support in this preset      |

Slack's discovery currently omits PKCE metadata, while its
[token endpoint documents `code_verifier`](https://docs.slack.dev/reference/methods/openid.connect.token/).
The preset supplies that missing capability only for Slack's pinned issuer and
endpoints. Explicit metadata that excludes S256 still fails configuration. Generic
OIDC providers keep their existing discovery requirements. Unexpected callback
`iss` values are rejected; the signed ID token must still have Slack's exact issuer.

Use `registrations` with one active generation and retired previous generations
for [credential rotation](../reference/oauth#configuration-rotation).
