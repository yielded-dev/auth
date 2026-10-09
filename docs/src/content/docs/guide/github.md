---
title: GitHub
description: Set up GitHub sign-in with Yielded Auth.
---

Sign in with a GitHub OAuth App. Start with [OAuth setup](./oauth).

## Get your credentials

Create an OAuth App in [GitHub developer settings](https://github.com/settings/developers).
Set its callback URL to `https://app.example.com/auth/github/callback`.

## Configure the provider

```ts title="apps/server/github.ts"
import { Redacted } from "effect";
import * as GitHub from "@yielded/auth/GitHub";
import { Http } from "@yielded/auth";

import { AppAuth } from "./auth";
import { config } from "./config";

export const AuthRoutes = Http.layer(AppAuth, {
  origin: config.AUTH_ORIGIN,
  oauth: {
    providers: {
      github: GitHub.provider({
        clientId: config.GITHUB_CLIENT_ID,
        clientSecret: Redacted.make(config.GITHUB_CLIENT_SECRET),
      }),
    },
  },
});
```

[Supply your services](../reference/oauth#supply-the-services) and keep the Layer
alive for the server's lifetime. `AuthRoutes` derives the callback URL from `origin`.
GitHub sign-in requests `read:user`. Its numeric user ID identifies the account;
profile email can be absent and needs application verification when required.

## Sign in

```ts
const auth = yield* AppAuth;
const started = yield* auth.signIn({
  provider: "github",
  returnTarget: "/account",
});
```

Redirect to `Redacted.value(started.authorizationUrl)`. The callback signs in an
existing account and returns to `returnTarget`. Use the
[registration flow](./oauth#register-new-users) for new accounts.

The [browser example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-client.ts)
shows the client and Atom workflow. To retain provider tokens, configure
[OAuth with an access profile](./oauth#sign-in-and-retain-provider-access).
