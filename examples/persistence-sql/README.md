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
[GitHub developer settings](https://github.com/settings/developers), or add the
callback to an existing app without replacing callbacks used by another consumer.
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
