# Authentication examples

Consumer examples compose public `@yielded/auth` exports with application-owned
identity, persistence, and delivery. `getting-started.ts` shows application
composition; `session-contract.ts` and `session-http.ts` show the minimal session
service, cookies, selected routes, and protected HttpApi group. The runnable password, email, phone, session, and proof programs
use local example data. Filled-byte keys are demo-only: generate independent random
32-byte keys for production, store them in your secret configuration, and retain
old key material while credentials or persisted records reference it.

`auth-contract.ts` owns the shared named API; `auth-server.ts` mounts it beside
application routes. `auth-client.ts` declares the client and its atoms;
`auth-react.ts` uses the application's standard Atom registry and React hooks.
`auth-ssr.ts` shows request-owned server rendering and browser hydration;
the host keeps each Scope alive until its render or mounted application finishes.

Run a declared example through `vp run -F @yielded/example-auth <task>`.
All consumer files are checked by the root validation command.
[CryptoLive](../shared/crypto.ts) chooses the portable first-party crypto backend
and shares Auth's admission service with password hashing. Password, TOTP, and
OAuth protectors come directly from Auth. Native `OpenIdConnect` and `GitHub`
providers receive HTTP and crypto services in the server Layer's application
scope; their clients and key caches live until that scope closes.

The Studio example's storage and HTTP Layers require `Postgres.Database`; provide
`Postgres.databaseLayer` with an Effect PostgreSQL client at the application boundary.
`makeStudioLive(binding)` also requires `TotpSecretKeys`. Supply its Layer alongside
the database Layer; shared dependencies stay visible in Layer requirements.

`login-contract.ts`, `login-server.ts`, and `login-client.ts` compose email OTP +
GitHub with shared sessions, HTTP, and Atom workflows. Google is optional.
See the [OAuth guide](../../docs/src/content/docs/guide/oauth.mdx) for setup.

`example:github`, `example:strava`, and `example:strava-mcp` build their Atom browser
client and run a single-owner OAuth application. `oauth-application.ts` composes
`Auth.make` with `OAuth.make({ access: profile })`; [shared OAuth storage](../shared/oauth/storage.ts) owns the
explicit Effect SQL schema and allowlisted account provisioning. Provider grants use
the same connected storage and refresh engine as authenticated account connections.
Open `/login` and configure the provider callback at `/auth/{provider}/callback`.
The storage uses `@yielded/auth-persistence/OAuthPersistence` without Drizzle.
See [OAuth setup](../../docs/src/content/docs/reference/oauth.md#runnable-examples)
for environment variables and the development-state reset.

The examples allow sign-in and current-owner grant metadata/use. Management requires
an application-owned exact-action verifier and is denied until one is installed.
Run cohort revocation maintenance through an application-owned scheduler if enabling
management for a provider that supports remote revocation.

## Shared GitHub callback host

`example:oauth-proxy` runs a callback server and two independent apps. Register
`https://auth.example.com/oauth-proxy/github/callback` on one GitHub OAuth App.
The [composition](src/oauth-proxy-application.ts) registers localhost and the
configured preview, and gives each app its own SQLite storage and sessions.

Publish the callback server and preview over HTTPS, forwarding to Bun on
`127.0.0.1` ports 4000 and 3001. Follow the
[hosting requirements](../../docs/src/content/docs/reference/oauth.md#hosting-and-recovery)
for forwarded headers, private upstream access, and callback logging.

Set these environment variables for each process:

| Process         | Configuration                                                                                                    |
| --------------- | ---------------------------------------------------------------------------------------------------------------- |
| Callback server | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `PROXY_ENCRYPTION_KEY`, `LOCAL_PROXY_SECRET`, `PREVIEW_PROXY_SECRET` |
| Each app        | `PROXY_SECRET`, `SESSION_KEY`, `OAUTH_TRANSACTION_KEY`, `GITHUB_USER_ID`                                         |

Generate independent keys and environment secrets from 32 random bytes encoded as
unpadded base64url. Each app's `PROXY_SECRET` matches its registration on the server.
Keep keys stable across restarts. Only the allowlisted `GITHUB_USER_ID` can sign in.

Run these in separate terminals from the repository root:

```sh
MODE=proxy APP_ORIGIN=https://auth.example.com PREVIEW_ORIGIN=https://preview.example.com \
  vp run @yielded/example-auth#example:oauth-proxy

MODE=local PROXY_URL=https://auth.example.com/oauth-proxy \
  vp run @yielded/example-auth#example:oauth-proxy

MODE=preview APP_ORIGIN=https://preview.example.com PROXY_URL=https://auth.example.com/oauth-proxy \
  vp run @yielded/example-auth#example:oauth-proxy
```

Open `http://localhost:3000/login` or `https://preview.example.com/login`.
After sign-in, `/account` shows that app's session. The example does not retain
provider API access.

For a later clean-start cutover, reset old accounts, auth/session/proof state,
per-account trips/conversations/settings/encrypted API keys, and browser caches.
Retire associated generated sites and build/address records. Allocate new subjects
and storage namespaces; users re-register and re-enter API keys. The consumer
release owns this reset; these examples perform no deletion.
