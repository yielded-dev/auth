# @yielded/auth-persistence

Direct Effect SQL persistence and shared storage contracts for `@yielded/auth`.

Import the named `AuthPersistence` facade and provide an explicit Effect SQL client
and Effect `Crypto` to its Layer. Managed storage requires a stable `prefix`; use
the existing table prefix when connecting an existing database.
Drizzle integrations live in `@yielded/auth-persistence-drizzle`; this package has
no Drizzle dependency or exports. Core workflows and replaceable service contracts
remain in `@yielded/auth`.

`OAuthPersistence` supplies upstream provider sign-in, registration, login linking and
unlinking, and retained grants through explicit table mappings on PostgreSQL and
SQLite with interactive transactions. Provide `SqlClient`, Effect `Crypto`, and
lifecycle hooks; applications own subjects, policies, keys, and migrations. See the
[OAuth adapter reference](../../docs/src/content/docs/reference/adapters.md#oauth)
and [runnable Effect SQL consumer](../../examples/persistence-sql).

`OAuthServerPersistence` supplies independent, single-table consent and grant
storage for [MCP authorization](../../docs/src/content/docs/guide/oauth.mdx#authorize-mcp-clients).
Its conditional writes and monotonic revocation require standalone commits.

`OAuthProxyPersistence` stores encrypted attempts for the
[OAuth callback proxy](../../docs/src/content/docs/reference/oauth.md#callback-proxy)
on SQLite/D1 or PostgreSQL. Its operations require standalone commits.

Applications own subject provisioning, policy, claims, delivery, and their database
connection and migration runner.

The composed Layer covers password sign-in and management, email address verification
and changes, phone sign-in, and passkey sign-in and management with stateful sessions
on PostgreSQL and SQLite. The `/Adapter` module has two integration levels:
typed table mappings, or `NativeSqlTables` with shared strategy factories. The same
native statements and commit owner serve direct SQL and Drizzle; drivers translate
physical columns and expressions and supply transaction or atomic-batch execution.
Plain reads use no transaction. Protected mutations retain their named final checks
when an application joins additional work to the owner.
See [persistence examples](../../docs/src/content/docs/reference/adapters.md#runnable-examples) for all
four ownership models and their current limits.
