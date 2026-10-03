# Effect SQL without Drizzle

A runnable account app with registration, email verification, password recovery,
passkey enrollment and sign-in, and custom hashing through direct Effect SQL.
The application owns its SQL migrations, customer IDs, table names, and column
representations. There are no Drizzle imports or dependencies.

```sh
vp -C examples/persistence-sql run start
```

Open <http://localhost:4183> and create an account. This example keeps its own
database and keys under `.data/`; accounts from the Drizzle examples are separate.
Set the Cloudflare credentials in [.env.example](.env.example) to deliver email
from `hello@effect-agent.com`.

The same app hosts the native browser-login examples at `/login`. With the default
clients, a fresh sign-in returns to Electron or iOS automatically; an existing
browser session first asks you to confirm the account. A manual return link
remains if the browser blocks opening the app. Native credentials use the
separate `/auth/native` transport; the browser keeps its own
session. See [browser-login.ts](src/browser-login.ts) for registered clients and
native admission. Run [the Electron example](../browser-login-electron) beside it.
The example requires authentication within five minutes for a new native session.
If confirmation rejects an older browser session, sign out and sign in again.

The default clients use custom schemes and keep existing-session confirmation.
To enable automatic reuse for a claimed HTTPS iOS callback, set both
`AUTH_IOS_RETURN_URL` (the exact public HTTPS callback URL on port 443) and
`AUTH_IOS_APP_ID` (the signed `PREFIX.bundle.identifier`). The server rejects
partial or invalid configuration. Configure the native client with that same
callback, and deploy the associated-domain entitlement and generated Apple
association document on the callback host before enabling it. See the
[browser-login guide](../../docs/src/content/docs/guide/browser-login.mdx).
The private development origin does not establish claimed-link device support.

For a physical iPhone, serve this app through a reachable HTTPS reverse proxy and
set `AUTH_ORIGIN` to that exact origin. `AUTH_PORT` defaults to `4183`; the server
binds loopback for the proxy. The origin configures cookies, CSRF and passkey RP
identity together. Existing localhost passkeys cannot authenticate for a different
RP; register credentials separately for that host. Never log native credential
headers or callback URLs at the proxy.

`vp -C examples/persistence-sql run start:pg` starts the same app with persistent
PostgreSQL through `@effect/sql-pglite`. Choose one server at a time. [data.ts](src/data.ts)
selects the client Layer; a deployed app can supply `@effect/sql-pg` or another
Effect SQLite client through the same `SqlClient` service.

[schema.ts](src/schema.ts) maps the SQL descriptors in [tables.ts](src/tables.ts)
and [passkey-tables.ts](src/passkey-tables.ts). [migrations.ts](src/migrations.ts)
owns versioned DDL for both dialects. [live.ts](src/live.ts) shows subject provisioning
joining the auth transaction through the same SQL client.

All three SQL examples import the same [AuthApi](../shared/account/contract.ts),
[AppAuth](../shared/account/auth.ts), and [client](../shared/account/email-client.ts).
This app's [live.ts](src/live.ts) supplies its persistence and account Layers.
Hashing, Cloudflare delivery, forms, and Atom workflows also live in
[shared/account](../shared/account).
Adding a passkey requires authentication from the last five minutes. Sign in again
when prompted; an older valid session still permits ordinary account reads.
