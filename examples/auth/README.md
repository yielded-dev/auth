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
`Auth.make` with `OAuth.make({ access: profile })`; `oauth-storage.ts` owns the
explicit libSQL schema and allowlisted account provisioning. Provider grants use
the same connected storage and refresh engine as authenticated account connections.
Open `/login` and configure the provider callback at `/auth/{provider}/callback`.
See [OAuth setup](../../docs/src/content/docs/reference/oauth.md#runnable-examples)
for environment variables and the development-state reset.

The examples allow sign-in and current-owner grant metadata/use. Management requires
an application-owned exact-action verifier and is denied until one is installed.
Run cohort revocation maintenance through an application-owned scheduler if enabling
management for a provider that supports remote revocation.

## Shared GitHub callback host

`example:oauth-proxy` runs a stable callback host or a local/preview app using
public `OAuthProxy` APIs. Register **one GitHub OAuth App callback**:
`https://auth.example.com/oauth-proxy/github/callback`. Both apps use that same
GitHub registration. The host registers exactly
`http://localhost:3000/auth/github/callback` for `local` and
`${PREVIEW_ORIGIN}/auth/github/callback` for `preview`.

Use a TLS reverse proxy or tunnel for the stable host and preview app, forwarding
to Bun on `127.0.0.1` (ports 4000 and 3001 by default). Preserve the public `Host`
and set `X-Forwarded-Proto: https` at this trusted boundary. The proxy checks the
exact external request origin; forwarding the upstream loopback Host fails.
Replace client-supplied forwarding headers and keep the upstream listener private;
`OAuthProxy.routes` reconstructs the public HTTPS URL on Bun before validation.
Disable callback URL logging at the reverse proxy too. Only the registered local
completion permits HTTP; `PROXY_URL` and both public host origins require HTTPS.

Generate each key and environment secret independently as base64url-encoded
32 random bytes (43 characters, no padding). Keep `PROXY_ENCRYPTION_KEY` and
GitHub's `GITHUB_CLIENT_SECRET` only on the host. Give each app only its own
`PROXY_SECRET`, matching the host's `LOCAL_PROXY_SECRET` or `PREVIEW_PROXY_SECRET`.
Use different `SESSION_KEY` and `OAUTH_TRANSACTION_KEY` values in each app.
Environment secrets authorize registered completions; the trusted host verifies
GitHub identity, while each app owns request binding, accounts, and sessions.

Set the relevant secrets in each process's environment, then run from the repo root:

```sh
# Host also needs GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, PROXY_ENCRYPTION_KEY,
# LOCAL_PROXY_SECRET and PREVIEW_PROXY_SECRET.
MODE=proxy APP_ORIGIN=https://auth.example.com PREVIEW_ORIGIN=https://preview.example.com \
  vp run @yielded/example-auth#example:oauth-proxy

# Each app needs PROXY_SECRET, SESSION_KEY, OAUTH_TRANSACTION_KEY and GITHUB_USER_ID.
MODE=local PROXY_URL=https://auth.example.com/oauth-proxy \
  vp run @yielded/example-auth#example:oauth-proxy

MODE=preview APP_ORIGIN=https://preview.example.com PROXY_URL=https://auth.example.com/oauth-proxy \
  vp run @yielded/example-auth#example:oauth-proxy
```

`PORT` overrides the Bun listener; the local completion remains fixed at
`http://localhost:3000`, so forward port 3000 if changing its listener.
`SQLITE_FILENAME` overrides each mode's independent default: `oauth-proxy.sqlite`,
`oauth-local.sqlite`, or `oauth-preview.sqlite`, relative to `examples/auth`.
The host applies the public persistence migration once using Effect SQL's migrator.
Retain its encryption key while attempts reference it; keep app keys stable across
restarts. Local and preview use the existing `GITHUB_USER_ID` allowlist fixture;
other GitHub users cannot sign in. Open each app's `/login`; `/account` requires
its own session. No provider access is retained and no token-encryption key is needed.

`oauth-proxy-application.ts` exports import-safe `makeProxyServer` and
`makeProxyEnvironment` compositions, including their live services and routes,
for direct workflow use. Supply an `HttpClient` Layer; the CLI uses Fetch.
The shared Atom browser client uses `OAuthSignInApi`; the existing GitHub and
Strava apps keep their richer `OAuthApi` and retained-grant behavior.

For a later clean-start cutover, reset old accounts, auth/session/proof state,
per-account trips/conversations/settings/encrypted API keys, and browser caches.
Retire associated generated sites and build/address records. Allocate new subjects
and storage namespaces; users re-register and re-enter API keys. The consumer
release owns this reset; these examples perform no deletion.
