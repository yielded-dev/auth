---
description: Understand OAuth sign-in, application sessions, and provider API access.
---

# OAuth

OAuth lets a user authorize your app through a provider such as Strava or GitHub.
Two things can come from that authorization: an **app session** identifies the
signed-in user; a **provider grant** lets your app call the provider's API.

| Your app needs                                                | Start with                 |
| ------------------------------------------------------------- | -------------------------- |
| Provider sign-in, retained API access, and stateless sessions | `OAuthApp`                 |
| OAuth alongside passwords, email, or other sign-in methods    | `OAuth` inside `Auth.make` |

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

```ts [auth.ts]
import { OAuthAppPersistence } from "@yielded/auth-persistence";
import * as OAuthApp from "@yielded/auth/OAuthApp";
import * as Strava from "@yielded/auth/Strava";
import { Layer, Schema } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { config, keys, resolveAccount, DatabaseLive } from "./app-services";

export const app = OAuthApp.make("strava", {
  claims: Schema.Struct({ role: Schema.Literals(["owner", "member"]) }),
  returnTargets: ["/account"],
});

const live = app
  .layer({
    origin: config.origin,
    ...keys,
    provider: Strava.provider({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      scopes: ["activity:read_all"],
    }),
  })
  .pipe(
    Layer.provide(Layer.succeed(app.Accounts, { resolve: resolveAccount })),
    Layer.provide(OAuthAppPersistence.layer),
    Layer.provide(DatabaseLive),
    Layer.provide(FetchHttpClient.layer),
  );

export const AuthRoutes = app.routes.pipe(Layer.provide(live));
```

`app-services` is your application code: `resolveAccount` maps a verified provider
identity to `{ subjectId, claims }`; `keys` supplies the three keyrings;
`DatabaseLive` supplies a migrated SQL connection. The
[runnable Strava example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/strava-app.ts)
shows that setup, including an athlete allowlist.

Mount `AuthRoutes`, register `/auth/strava/callback` with Strava at your app's
origin, and link to `/auth/strava/sign-in`. Successful sign-in redirects to `/account`.
See the [setup reference](../reference/oauth#managed-app-setup) for keys, storage,
and callback tracing.

### Use the session and provider access

Inside a server Effect, verify the session cookie and use its connection:

<!-- prettier-ignore -->
```ts
const sessions = yield* app.Sessions;
const session = yield* sessions.verify(credential); // Redacted cookie value
const oauth = yield* app.Service;
yield* oauth.withAccessToken(session, syncActivities); // receives a Redacted token
```

Background jobs can use a connection reference saved in trusted application storage.
The library refreshes tokens before calling your function and never retries its work.

These sessions have a fixed expiry. Sign-out clears the cookie; it does not revoke
an already issued session. Disconnect stops local provider access. See
[session and connection behavior](../reference/oauth#sessions-and-connections).

## OAuth in a shared auth service

Add an OAuth strategy when users share sessions across several sign-in methods:

```ts [auth.ts]
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
