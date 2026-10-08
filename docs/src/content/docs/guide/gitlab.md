---
title: GitLab
description: Set up Sign in with GitLab using the shared OIDC flow.
---

`GitLab.provider` adds Sign in with GitLab to an [OAuth strategy](./oauth).
It verifies an ID token and establishes your application's session. The preset
does not retain GitLab API access.

## Configure your GitLab application

Create an application in [GitLab](https://gitlab.com/-/user_settings/applications)
or your self-hosted instance. Register `https://app.example.com/auth/gitlab/callback`
and enable the `openid`, `profile`, and `email` scopes.
See [GitLab OpenID Connect](https://docs.gitlab.com/ee/integration/openid_connect_provider.html).

Load the credentials while building the server Layer:

```ts title="apps/server/gitlab.ts"
import { Config, Effect, Layer } from "effect";
import { GitLab, Http } from "@yielded/auth";

import { AppAuth } from "./auth";

export const AuthRoutes = Layer.unwrap(
  Effect.gen(function* () {
    return Http.layer(AppAuth, {
      origin: yield* Config.String("APP_ORIGIN"),
      oauth: {
        providers: {
          gitlab: GitLab.provider({
            clientId: yield* Config.String("GITLAB_CLIENT_ID"),
            clientSecret: yield* Config.Redacted("GITLAB_CLIENT_SECRET"),
            scopes: ["openid", "profile", "email"],
          }),
        },
      },
    });
  }),
);
```

[Supply HTTP, crypto, persistence and application services](../reference/oauth#supply-the-services)
to this Layer. The default issuer is `https://gitlab.com`. Pass `issuer` for a
self-hosted instance; Yielded preserves the exact value, including an optional
trailing slash. The default scope is `openid`.

## Identity and group policy

The durable identity is `(provider key, issuer, verified sub)`. Keep `sub`
unchanged. Group lists in `GitLabUserProfile` are application policy, not local
identity. Never link accounts merely because profile emails match.

```ts
const social = OAuth.make({ profiles: { gitlab: GitLab.GitLabUserProfile } });
```

The resolver can read `identity.profile?.providerData?.groups` as
`string[] | undefined`. GitLab does not advertise RFC 9207 `iss`; give this
provider a distinct callback URL.

## Run the example

The [GitLab application](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/gitlab-app.ts)
provisions one configured GitLab user.

1. Forward an HTTPS development origin to `127.0.0.1:3000`. Set `APP_ORIGIN` to that
   public origin and register `/auth/gitlab/callback`.
2. Set `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET`, and `GITLAB_USER_ID` (the GitLab
   `sub`). Optionally set `GITLAB_ISSUER` for a self-hosted instance.
3. Set `SESSION_KEY` and `OAUTH_TRANSACTION_KEY` to distinct base64url encodings of
   32 random bytes. Preserve these keys across restarts.
4. Run `vp run @yielded/example-auth#example:gitlab` from the repository root and open
   `APP_ORIGIN/login`.

The example stores development state in `examples/auth/gitlab-auth.sqlite`. Stop
the example and remove only that database and its SQLite sidecar files to start
over.

## Protocol profile

| Concern                  | Behavior                                                         |
| ------------------------ | ---------------------------------------------------------------- |
| Issuer                   | `https://gitlab.com` or the configured self-hosted issuer        |
| Authorization / callback | `/oauth/authorize`, authorization code, query response           |
| Token exchange           | `/oauth/token`, `client_secret_basic`                            |
| Signature                | Advertised RS256; issuer, audience, expiry and nonce verified    |
| PKCE                     | S256                                                             |
| Response issuer          | GitLab does not advertise RFC 9207 `iss`; use a distinct callback |
| Access                   | Sign-in only; no retained API access                             |
