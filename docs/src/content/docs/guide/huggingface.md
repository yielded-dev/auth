---
title: Hugging Face
description: Set up Sign in with Hugging Face using the shared OIDC flow.
---

`HuggingFace.provider` adds Sign in with Hugging Face to an [OAuth strategy](./oauth).
It verifies an ID token and establishes your application's session.

Create an OAuth application and register `https://app.example.com/auth/huggingface/callback`.
See [Sign in with Hugging Face](https://huggingface.co/docs/hub/oauth).

```ts title="apps/server/huggingface.ts"
import { Config, Effect, Layer } from "effect";
import { Http, HuggingFace } from "@yielded/auth";

import { AppAuth } from "./auth";

export const AuthRoutes = Layer.unwrap(
  Effect.gen(function* () {
    return Http.layer(AppAuth, {
      origin: yield* Config.String("APP_ORIGIN"),
      oauth: {
        providers: {
          huggingface: HuggingFace.provider({
            clientId: yield* Config.String("HUGGINGFACE_CLIENT_ID"),
            clientSecret: yield* Config.Redacted("HUGGINGFACE_CLIENT_SECRET"),
            scopes: ["openid", "profile", "email"],
          }),
        },
      },
    });
  }),
);
```

[Supply HTTP, crypto, persistence and application services](../reference/oauth#supply-the-services).
The durable identity is `(provider key, "https://huggingface.co", verified sub)`.
Declare `profiles: { huggingface: HuggingFace.HuggingFaceUserProfile }` for typed
`providerData`. Hugging Face does not advertise RFC 9207 `iss`; give this provider
a distinct callback.

Run `vp run @yielded/example-auth#example:huggingface` with `APP_ORIGIN`,
`HUGGINGFACE_CLIENT_ID`, `HUGGINGFACE_CLIENT_SECRET`, `HUGGINGFACE_USER_ID`,
`SESSION_KEY`, and `OAUTH_TRANSACTION_KEY`. Register `/auth/huggingface/callback`
on an HTTPS origin forwarded to `127.0.0.1:3000`. Development state is
`examples/auth/huggingface-auth.sqlite`.

| Concern         | Behavior                                           |
| --------------- | -------------------------------------------------- |
| Issuer          | Exact `https://huggingface.co`                     |
| Token exchange  | `client_secret_basic`, S256 PKCE, advertised RS256 |
| Response issuer | Not advertised; use a distinct callback            |
| Access          | Sign-in only                                       |
