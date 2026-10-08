---
title: Vercel
description: Set up Sign in with Vercel using the shared OIDC flow.
---

`Vercel.provider` adds Sign in with Vercel to an [OAuth strategy](./oauth).
It verifies an ID token and establishes your application's session.

Create a Vercel OAuth app and register `https://app.example.com/auth/vercel/callback`.
See [Sign in with Vercel](https://vercel.com/docs/sign-in-with-vercel).

```ts title="apps/server/vercel.ts"
import { Config, Effect, Layer } from "effect";
import { Http, Vercel } from "@yielded/auth";

import { AppAuth } from "./auth";

export const AuthRoutes = Layer.unwrap(
  Effect.gen(function* () {
    return Http.layer(AppAuth, {
      origin: yield* Config.String("APP_ORIGIN"),
      oauth: {
        providers: {
          vercel: Vercel.provider({
            clientId: yield* Config.String("VERCEL_CLIENT_ID"),
            clientSecret: yield* Config.Redacted("VERCEL_CLIENT_SECRET"),
            scopes: ["openid", "profile", "email"],
          }),
        },
      },
    });
  }),
);
```

[Supply HTTP, crypto, persistence and application services](../reference/oauth#supply-the-services).
The durable identity is `(provider key, "https://vercel.com", verified sub)`.
Declare `profiles: { vercel: Vercel.VercelUserProfile }` for typed `providerData`.
Vercel does not advertise RFC 9207 `iss`; give this provider a distinct callback.

Run `vp run @yielded/example-auth#example:vercel` with `APP_ORIGIN`,
`VERCEL_CLIENT_ID`, `VERCEL_CLIENT_SECRET`, `VERCEL_USER_ID`, `SESSION_KEY`, and
`OAUTH_TRANSACTION_KEY`. Register `/auth/vercel/callback` on an HTTPS origin
forwarded to `127.0.0.1:3000`. Development state is `examples/auth/vercel-auth.sqlite`.

| Concern         | Behavior                                           |
| --------------- | -------------------------------------------------- |
| Issuer          | Exact `https://vercel.com`                         |
| Token exchange  | `client_secret_basic`, S256 PKCE, advertised RS256 |
| Response issuer | Not advertised; use a distinct callback            |
| Access          | Sign-in only                                       |
