# @yielded/auth-persistence

Direct Effect SQL persistence and shared storage contracts for `@yielded/auth`.

Import the named `AuthPersistence` facade and provide an explicit Effect SQL client.
Drizzle integrations live in `@yielded/auth-persistence-drizzle`; this package has
no Drizzle dependency or exports. Core workflows and replaceable service contracts
remain in `@yielded/auth`.

`OAuthAppPersistence` separately supplies the single-table store for
[`OAuthApp`](../../docs/guide/oauth.md#sign-in-and-connect-provider-access).
It has no dependency on the broader auth schema or a session repository. Apply its
exported migration with the application's runner and provide an Effect SQL client.

`OAuthServerPersistence` supplies independent, single-table consent and grant
storage for [MCP authorization](../../docs/guide/oauth.md#authorize-mcp-clients).
Its conditional writes and monotonic revocation require standalone commits.

Applications own subject provisioning, policy, claims, delivery, and their database
connection and migration runner.

The composed Layer covers password sign-in and management, email address verification
and changes, phone sign-in, and passkey sign-in and management with stateful sessions
on PostgreSQL and SQLite. The `/Adapter` module exposes the shared mapping contracts
and transaction kernels used by companion adapters.
See [persistence examples](../../docs/reference/adapters.md#runnable-examples) for all
four ownership models and their current limits.
