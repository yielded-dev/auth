# @yielded/auth-persistence

SQL algorithms, Drizzle bindings, and opt-in managed schemas for `@yielded/auth`.
Both packages release together at the same version.

Import the named `AuthPersistence` facade from this package for direct Effect SQL,
or from `@yielded/auth-persistence/drizzle/<driver>` for Drizzle. The raw entry point
does not require Drizzle. Core workflows and replaceable service contracts remain
in `@yielded/auth`.

`OAuthAppPersistence` separately supplies the single-table store for
[`OAuthApp`](../../docs/guide/oauth.md#sign-in-and-connect-provider-access).
It has no dependency on the broader auth schema or a session repository. Apply its
exported migration with the application's runner and provide an Effect SQL client.

`OAuthServerPersistence` supplies independent, single-table consent and grant
storage for [MCP authorization](../../docs/guide/oauth.md#authorize-mcp-clients).
Its conditional writes and monotonic revocation require standalone commits.

Applications own subject provisioning, policy, claims, delivery, and their database
connection. Drizzle Kit generates migrations from managed or application-declared
Drizzle tables. Install `AuthPersistence.migrationsLayer({ migrationsFolder })`
explicitly to apply those files before starting auth; direct SQL applications own
their migration runner.

The composed Layer covers password sign-in and management, email address verification
and changes, phone sign-in, and passkey sign-in and management with stateful sessions
on PostgreSQL and SQLite. Explicit Drizzle adapter factories cover the other workflows.
See [persistence examples](../../docs/reference/adapters.md#runnable-examples) for all
four ownership models and their current limits.
