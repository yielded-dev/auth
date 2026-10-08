---
title: Google
description: Set up Sign in with Google using the shared OIDC flow.
---

`Google.provider` adds Sign in with Google to an [OAuth strategy](./oauth).
It verifies an ID token and establishes your application's session. The preset
does not retain Google API access.

## Configure your Google Cloud client

Create an OAuth client in the [Google Cloud console](https://console.cloud.google.com/apis/credentials).
Add `https://app.example.com/auth/google/callback` as an authorized redirect URI.
Find the client ID and client secret on the client.

Load the credentials while building the server Layer:

```ts title="apps/server/google.ts"
import { Config, Effect, Layer } from "effect";
import { Google, Http } from "@yielded/auth";

import { AppAuth } from "./auth";

export const AuthRoutes = Layer.unwrap(
  Effect.gen(function* () {
    return Http.layer(AppAuth, {
      origin: yield* Config.String("APP_ORIGIN"),
      oauth: {
        providers: {
          google: Google.provider({
            clientId: yield* Config.String("GOOGLE_CLIENT_ID"),
            clientSecret: yield* Config.Redacted("GOOGLE_CLIENT_SECRET"),
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
Start with `auth.signIn({ provider: "google", returnTarget: "/account" })` and
redirect to the returned authorization URL. The callback completes sign-in.

The preset always sends `prompt=select_account` and `access_type=offline`.
`auth.signIn` can still pass a per-request `prompt` or `loginHint`. Offline access
does not install retained Google API grants; add connected `access` on a generic
OIDC registration when you keep refresh tokens.

## Identity and Workspace policy

The durable identity is `(provider key, "https://accounts.google.com", verified sub)`.
Keep `sub` unchanged; neither the email address nor hosted domain identifies a
local account. Never link accounts merely because profile emails match, even when
`email_verified` is true.

Declare `profiles` on the strategy to get typed `providerData` in
`SessionClaims.resolve`:

```ts
const social = OAuth.make({ profiles: { google: Google.GoogleUserProfile } });
```

The library validates the schema before calling your resolver, which can read
`identity.profile?.providerData?.hd` as `string | undefined` without decoding it
again. Fields absent from the ID token stay absent; no UserInfo request is made.

The optional `hd` provider option hints which Workspace domain to show on Google's
account picker. It does not restrict membership. Applications requiring a domain
must compare the verified `hd` claim against their own policy and reject missing
or different values before issuing a session. The runnable example does this when
`GOOGLE_HOSTED_DOMAIN` is set.

## Run the example

The [Google application](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/google-app.ts)
uses the shared Atom browser client, SQL identity storage, and stateless sessions.
It provisions one explicitly configured Google user and rejects other identities.

1. Forward an HTTPS development origin to `127.0.0.1:3000`. Set `APP_ORIGIN` to that
   public origin and register its `/auth/google/callback` URL on the OAuth client.
2. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_USER_ID` (the Google
   `sub`). Optionally set `GOOGLE_HOSTED_DOMAIN` to the Workspace domain the
   verified `hd` claim must match.
3. Set `SESSION_KEY` and `OAUTH_TRANSACTION_KEY` to distinct base64url encodings of
   32 random bytes. For example, run `openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'`
   separately for each key. Preserve these keys across restarts.
4. Run `vp run @yielded/example-auth#example:google` from the repository root and open
   `APP_ORIGIN/login`. Sign in with the configured Google account.
5. After the callback, `/account` returns the local `subjectId` and `role: "owner"`.
   A different subject or hosted domain must not receive a session.

The example stores development state in `examples/auth/google-auth.sqlite`. To
start over, stop the example, remove only that database and its SQLite sidecar
files, and clear cookies for the development origin. This resets this example's
account link and flows. No provider grant is retained, so `OAUTH_TOKEN_KEY` is
not needed.

## Protocol profile

The preset uses Google's [discovery document](https://accounts.google.com/.well-known/openid-configuration)
with these constraints:

| Concern                  | Behavior                                                                                   |
| ------------------------ | ------------------------------------------------------------------------------------------ |
| Issuer                   | Exact `https://accounts.google.com`                                                        |
| Authorization / callback | `/o/oauth2/v2/auth`, authorization code, query response                                    |
| Token exchange           | `https://oauth2.googleapis.com/token`, `client_secret_post`                                |
| Signature                | Advertised RS256, keys at Google's JWKS; issuer, audience, expiry and nonce verified       |
| PKCE                     | S256 challenge and captured verifier on every exchange                                     |
| Response issuer          | Google advertises RFC 9207 `iss`                                                           |
| Access                   | Sign-in only; `access_type=offline` is sent; no retained access is installed in this preset |

Use `registrations` with one active generation and retired previous generations
for [credential rotation](../reference/oauth#configuration-rotation).
