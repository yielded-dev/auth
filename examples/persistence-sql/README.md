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

The current schema replaces the old proof tables with one current-code table.
Reset this example's development database before running it against older data;
this also resets its accounts, sessions, and credentials.

## Native browser sign-in

`/login` also serves [the Electron example](../browser-login-electron) and iOS
clients. Fresh sign-in returns automatically; an existing session asks for
confirmation. Authentication must be within five minutes, so an older session
may need to sign in again.

For a physical iPhone, put a reachable HTTPS reverse proxy in front of the server
and set `AUTH_ORIGIN` to that origin. `AUTH_PORT` defaults to `4183`; the server
binds loopback. Passkeys are tied to the configured host.

To reuse an existing session automatically, configure the iOS client with an
associated HTTPS callback and set `AUTH_IOS_RETURN_URL`, for example to your
web account page at `https://app.example.com/account`. Deploy and verify the
app/domain association first; see [association setup](../../docs/src/content/docs/reference/browser-login.md#apple-association).
The default registrations in [browser-login.ts](src/browser-login.ts) use custom schemes.

## Storage

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

## OAuth account settings

Run the browser journey with a GitHub OAuth App. Create an app in
[GitHub developer settings](https://github.com/settings/developers). A GitHub OAuth
App has one callback URL; use a separate development app when its existing callback
serves another consumer.
Set the callback URL to `http://localhost:4185/oauth-settings/callback` for local
use, or `https://YOUR_HOST/oauth-settings/callback` for a hosted preview.

Supply `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `GITHUB_USER_ID` through
your server environment. The user ID is GitHub's numeric, stable ID (`gh api user
--jq .id`), not a username. Then run:

```sh
AUTH_DATA_DIR=/tmp/yielded-oauth-github \
  vp -C examples/persistence-sql run start:oauth
```

Open <http://localhost:4185/oauth-settings> and sign in with the configured GitHub
account. Choose **Link another account** and select a second GitHub account you
control. Both appear in the public `listLinkedAccounts` query. Remove one, sign in
with the remaining identity, then try removing the last one: the server refuses to
lock you out. Cancel consent to leave the inventory unchanged. Linking an identity
owned by another application account reports an ownership conflict with recovery
steps; re-linking your current identity leaves its existing link intact.

The configured user ID provisions the first account once. Changing it later does
not replace existing links. This example has no public registration or email-based
account matching. Use a fresh data directory when switching from the earlier
Strava demo; its persisted provider identities are not GitHub identities.

`AUTH_PORT` defaults to `4185`. For an HTTPS reverse proxy, set `AUTH_ORIGIN` to
the external origin and register its exact callback URL; cookies become Secure.
The server binds `127.0.0.1`, so the reverse proxy must run on the same host. A
[Cloudflare Quick Tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)
can provide a temporary preview: start `cloudflared tunnel --url http://127.0.0.1:4185`,
then use its HTTPS URL as `AUTH_ORIGIN`. Keep both processes running; a new tunnel
URL requires a matching callback registration.

GitHub requests `read:user` for sign-in. This app retains no provider grants and
keeps client secrets on the server. Tokens never enter session claims, browser
results, persistent storage or logs. Consent and code exchange use GitHub's real
endpoints; there is no simulated browser provider. See
[GitHub OAuth setup](../../docs/src/content/docs/guide/github.md).

### Policy, storage and client ownership

[The server](src/oauth-settings-server.ts) composes direct SQL mappings with
state-assisted signed sessions. Every session read checks the active subject and
security revision in the same database that owns account changes. Unlink removes
the credential and advances that revision in one transaction, invalidating every
session immediately. The eligibility mapping refuses to remove the last usable
primary sign-in method. Linking preserves the security revision and session.

[The application policy](src/oauth-settings-auth.ts) accepts an actual verified
session from the last five minutes, retaining its private factor identities,
revisions and original proof times. An older session must sign in again. The link
callback uses the authorization captured at begin and asks for no second proof.
This policy treats recent provider sign-in as sufficient confirmation; applications
requiring a separate factor should supply their own `OAuthActionEvidence`.

`AUTH_DATA_DIR` holds `auth.sqlite` and `oauth-settings-keys.json`, whose independent
random signing, transaction-encryption and binding keys are created with mode
`0600`. Keep keys stable across restarts and protect their directory. Set
`PERSISTENCE_DIALECT=pg` to use persistent PGlite in `postgres/` through the same
SQL mappings. Provisioning runs only for a new subject, so restarting cannot
restore a removed login. Reset only the chosen disposable directory and this
example's browser cookies to start over; this removes all its identities, sessions,
flows and keys. Deployed applications should own migrations, key rotation, expired
flow/tombstone cleanup, account provisioning and provider access policy.

[The shared contract](src/oauth-settings-contract.ts) exposes public package
operations. [Effect Atom](src/oauth-settings-client.ts) owns sign-in, redirect
metadata, callback completion, paginated listing and unlink. Named auth mutations
invalidate the listing automatically. React only renders and dispatches. The
callback consumes one attempt, clears code/state from browser history, and never
automatically retries an uncertain exchange. Session storage contains only the
attempt kind, public flow ID and expiry. Start again after expiry or cancellation;
after an uncertain response, inspect the current inventory before a new action.

## Shared Yielded sign-in

Set `YIELDED_AGENT_CLIENT_SECRET` to enable the OpenID server in the same app.
Agent must supply that exact secret as `AUTH_YIELDED_CLIENT_SECRET`, register
provider `yielded` with issuer `AUTH_ORIGIN`, and use client ID `yielded-agent`.
`YIELDED_AGENT_ORIGIN` defaults to `https://agent.yielded.dev`; its registered
callback is `${YIELDED_AGENT_ORIGIN}/travel/auth/yielded/callback`. The GitHub app
still has just the Auth callback `${AUTH_ORIGIN}/oauth-settings/callback`.

Run the same `start:oauth` command. Start at Agent's login page, choose **Continue
with Yielded**, sign in through GitHub if needed, and confirm **Continue to Yielded
Agent**. Cancel returns an actionable cancellation to Agent. Choose **Use another
account** to return to the Auth sign-in page. The account-settings page remains at
`/oauth-settings`; `/sign-in` continues the pending shared sign-in request.

[The composition](src/oauth-settings-application.ts) combines `OAuthServer.makeOpenId`
with the existing session verifier and SQL owner. [The identity service](src/yielded-identity.ts)
checks session revocation and the current subject security revision before code
redemption and UserInfo access. The app exposes only a stable account ID and
`YIELDED_DISPLAY_NAME` (default `Yielded member`). It provisions one configured
GitHub owner; public registration and a multi-user directory are outside this example.

Local startup creates `yielded-identity-keys.json` in `AUTH_DATA_DIR` with mode
`0600`: a private RSA signing key, its public JWK, and a separate consent key.
Keep this file and `oauth-settings-keys.json` stable and private. Only public JWKS
is served. The same SQL database owns `yielded_oauth_server` grants and client
assertion replay receipts; tokens and client secrets never enter those rows.
Each application needs a separate client secret and exact callback registration.

Auth and Agent use separate host-only sessions. Signing out of Auth revokes
subsequent identity access; already established Agent sessions remain until Agent
signs them out. Sync and docs can adopt separate OpenID clients later; this example
registers only Agent. It does not supply global logout or claim OpenID certification.

### Permanent Cloudflare host

The existing leaf app also deploys as a Worker with a SQLite Durable Object:

```sh
vp -C examples/persistence-sql run deploy:oauth
```

[alchemy.oauth.ts](alchemy.oauth.ts) owns the separate `yielded-auth` production
stack and the `auth.yielded.dev` custom domain. Supply Cloudflare account credentials,
the GitHub variables above, `YIELDED_DISPLAY_NAME`, `YIELDED_AGENT_CLIENT_SECRET`,
and two secret bindings: `AUTH_SETTINGS_KEYS` and `AUTH_IDENTITY_KEYS`, containing
the respective key-file JSON. Read them through your secret manager, not shell
history or public build variables. Browser assets contain no secrets.

Cloudflare owns the hostname's DNS and certificate in the configured Yielded zone.
Use a Worker custom domain: Agent's same-zone `fetch` calls can reach it without
a service binding, whereas a Worker route cannot receive those calls. Remove a
conflicting CNAME before attaching the domain.
The GitHub callback is `https://auth.yielded.dev/oauth-settings/callback`; discovery
is `https://auth.yielded.dev/.well-known/openid-configuration`. The documentation
site at `yielded.dev/auth/` remains a separate deployment.

The binding `AUTH`, class `HostedAuth`, and instance `yielded-auth-v1` identify
persistent state; keep them unchanged across deployments. The host supplies the
full Durable Object storage to `@effect/sql-sqlite-do` so link/unlink and authority
changes share one transaction owner. It uses the same provisioning and policy as
local SQL. A fresh deployment provisions the initial owner; it does not import
an existing local database. Migrate existing identities, revisions and revocations
explicitly before moving an established installation. Back up data and keys before
cutover. Request logs and traces are disabled to exclude OAuth credentials.

## OAuth lifecycle

Run a native CLI consumer with direct Effect SQL storage:

```sh
AUTH_DATA_DIR=/tmp/yielded-oauth-sqlite PERSISTENCE_DIALECT=sqlite \
  vp -C examples/persistence-sql run example:oauth-lifecycle

AUTH_DATA_DIR=/tmp/yielded-oauth-pg PERSISTENCE_DIALECT=pg \
  vp -C examples/persistence-sql run example:oauth-lifecycle
```

The consumer signs in, retains an encrypted grant, links another login identity,
lists grants, unlinks the login, rejects an absent-link retry, registers a new user,
and signs that user in. It closes and reopens its SQL client, then lists and uses
the original retained grant. Login links and provider API grants are separate:
`listAccountConnections` lists grants; `listLinkedAccounts` reads login identities.

The native Strava protocol uses simulated provider HTTP replies, so no provider
account or secret is needed. The CLI privately receives demo action codes in place
of an external delivery channel. SQL stores only their digests, binds them to an
action, command, and subject revision, and consumes them once. Public demo keys
are unsuitable for real credentials. This proves the library workflow and SQL
boundary, not real provider consent, browser cookies, or production factor delivery.

[The entrypoint](src/oauth-lifecycle.ts) composes the same
[application-owned mappings](../shared/oauth/storage.ts) as the live GitHub/Strava
examples. [Lifecycle storage](src/oauth-lifecycle-storage.ts) adds registration
and account-management mappings. Both dialects use the same tables; PostgreSQL
runs through PGlite with native `bigint` decoding. Only these two dialects are shown.

Keep the data directory to replay against persisted state. Each run adds a new
registered demo identity. Reset only the chosen disposable `AUTH_DATA_DIR` to start
over; these commands use separate directories from the browser account app.
