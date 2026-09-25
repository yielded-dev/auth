---
title: OAuth
description: Understand OAuth sign-in, application sessions, and provider API access.
---

OAuth lets a user authorize your app through a provider such as GitHub or Google.
Two things can come from that authorization: an **app session** identifies the
signed-in user; a **provider grant** lets your app call the provider's API.

| Your app needs                                                | Start with                              |
| ------------------------------------------------------------- | --------------------------------------- |
| Provider sign-in, retained API access, and stateless sessions | `OAuthApp`                              |
| OAuth alongside passwords, email, or other sign-in methods    | `OAuth` inside `Auth.make`              |
| Let an MCP client access your application                     | `OAuthServer` with Effect's `McpServer` |

## Sign in and connect provider access

`OAuthApp` manages the redirect, callback, session cookie, and provider tokens.
Your account policy decides who may sign in and which claims belong in the session.

```text
Browser → Provider consent → OAuthApp callback
                                   ↓
                            Your account policy
                              ├─ Signed session → Browser
                              └─ Encrypted grant → SQL

Your app / jobs → OAuthApp → Provider API
                     ↕
               Grant in SQL
```

Sessions verify without a database lookup. Pending flows and provider grants live
in one auth table; provider tokens refresh when your app needs them.

```ts title="auth.ts"
import { OAuthAppPersistence } from "@yielded/auth-persistence";
import * as OAuthApp from "@yielded/auth/OAuthApp";
import * as GitHub from "@yielded/auth-openid-client/GitHub";
import * as OAuthCrypto from "@yielded/auth-crypto/OAuth";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { Layer, Schema } from "effect";
import { config, keys, resolveAccount, DatabaseLive } from "./app-services";

export const app = OAuthApp.make("github", {
  claims: Schema.Struct({ role: Schema.Literals(["owner", "member"]) }),
  returnTargets: ["/account"],
});

const live = app
  .layer({
    origin: config.origin,
    sessionKeys: keys.session,
    provider: GitHub.appProvider({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: ["read:user"],
    }),
  })
  .pipe(
    Layer.provide(OAuthCrypto.transactionLayer(keys.transaction)),
    Layer.provide(OAuthCrypto.connectedTokenLayer(keys.token)),
    Layer.provide(layerWebCrypto),
    Layer.provide(Layer.succeed(app.Accounts, { resolve: resolveAccount })),
    Layer.provide(OAuthAppPersistence.layer),
    Layer.provide(DatabaseLive),
  );

export const AuthRoutes = app.routes.pipe(Layer.provide(live));
```

`app-services` is your application code: `resolveAccount` maps a verified provider
identity to `{ subjectId, claims }`; `keys` supplies distinct `session`,
`transaction`, and `token` keyrings; `DatabaseLive` supplies a migrated SQL
connection. The
[runnable GitHub example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/github-app.ts)
shows that setup, including an account allowlist.

Install `@yielded/auth-openid-client`, `@yielded/auth-crypto`, and `openid-client`.
Mount `AuthRoutes` and register `/auth/github/callback` at your app's
origin in your GitHub OAuth App. Link to `/auth/github/sign-in`. Successful sign-in redirects to `/account`.
See the [setup reference](../reference/oauth#managed-app-setup) for keys, storage,
and callback tracing.

### Use the session and provider access

Inside a server Effect, verify the session cookie and use its connection:

<!-- prettier-ignore -->
```ts
const sessions = yield* app.Sessions;
const session = yield* sessions.verify(credential); // Redacted cookie value
const oauth = yield* app.Service;
yield* oauth.withAccessToken(session, readProfile); // receives a Redacted token
```

For background jobs, save `{ subjectId, grantId }` from a verified session in your
application's storage. The library refreshes tokens before calling your function
and never retries its work.

These sessions have a fixed expiry. Sign-out clears the cookie; it does not revoke
an already issued session. Disconnect stops local provider access. See
[session and connection behavior](../reference/oauth#sessions-and-connections).

## Authorize MCP clients

`OAuthServer` lets a signed-in user grant a registered MCP client access to your
application. `OAuthApp` can supply the login session; it continues to own any
upstream provider credentials. The two grants stay separate:

```text
Browser → Application login → OAuthServer consent → MCP client
                                                      ↓ MCP token
                                                Effect McpServer
                                                      ↓ Authenticated subject
                                             Your handler and policy
                                                      ↓ Optional provider access
                                             OAuthApp → Provider API
```

Define supported scopes, supply an identity service that verifies your existing
session, and mount the authorization routes beside Effect's MCP routes:

```ts
const oauth = OAuthServer.make("mcp", { scopes: ["athlete:read"] });

const protectedMcp = McpServer.toolkit(toolkit).pipe(
  Layer.provide(handlers),
  Layer.provide(
    McpServer.layerHttp({
      name: "Athlete tools",
      version: "1.0.0",
      path: "/mcp",
      protocols: [McpProtocol.v2026_07_28],
    }),
  ),
  Layer.provide(oauth.middleware(["athlete:read"]).layer),
);
```

The [runnable Strava MCP example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/strava-mcp.ts)
provides the login, SQL migration, signing keys, client registration, CORS, and
server. It uses the built-in consent page and a single allowlisted athlete; its
tool returns the authenticated subject without calling Strava's API.

Inside a tool handler, read `OAuthServer.CurrentAccess`; reject `undefined`.
The value contains the authenticated `subjectId`, `clientId`, resource, scopes,
and grant ID. Your application still decides which accounts and operations that
subject may access. Your application owns the subject-to-provider connection
mapping. Resolve that connection from trusted storage, then call `withAccessToken`
on the service obtained from `app.Service`; MCP clients never receive provider tokens.

This initial server supports explicitly registered public clients. Clients must
support supplying their registered client ID; there is no dynamic registration
or Client ID Metadata Document endpoint. See the
[authorization server reference](../reference/oauth#authorization-server) for
the setup and token lifecycle.

## OAuth in a shared auth service

Add an OAuth strategy when users share sessions across several sign-in methods:

```ts title="auth.ts"
import { Auth, Sessions } from "@yielded/auth";
import { OAuth } from "@yielded/auth/strategies";
import { AuthApi } from "./auth-contract";

export const AppAuth = Auth.make(AuthApi, {
  sessions: Sessions.stateful(),
  strategies: { social: OAuth.make() },
  defaultStrategy: "social",
});
```

Declare the [OAuth actions and services](../reference/oauth#shared-auth-setup),
then configure [GitHub](./github) or [Google](./google). `Http.layer` mounts their
callbacks and delivers session cookies. `OAuth.make` uses existing account links;
`OAuth.makeRegistration` adds account creation.

### Email and social login

The [combined login example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-server.ts)
shares sessions across email, GitHub, and Google. Your app collects any signup
data needed when OAuth returns `RegistrationRequired`.

## Other providers

For shared auth, `OpenIdClient.provider` supports OIDC discovery and plain OAuth
endpoints. For a managed app, implement `OAuthApp.Provider` to return verified
identity and provider tokens. See [provider configuration](../reference/oauth#providers).

## Accounts and API access

| Task in shared auth        | API                      |
| -------------------------- | ------------------------ |
| Sign in                    | `OAuth.make`             |
| Create an account          | `OAuth.makeRegistration` |
| Link a login method        | `OAuth.makeAccounts`     |
| Retain provider API access | `OAuth.makeConnected`    |

Your app owns account identity and permissions. Provider profiles supply display
metadata; an email match is never permission to link accounts. The
[GitHub API example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/github-oauth-app.ts)
shows connected grants with shared auth.
