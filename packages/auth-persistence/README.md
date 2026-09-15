# @yielded/auth-persistence

SQL algorithms, Drizzle bindings, and opt-in managed schemas for `@yielded/auth`.
Both packages release together at the same version.

Import the named `AuthPersistence` facade from this package for direct Effect SQL,
or from `@yielded/auth-persistence/drizzle/<driver>` for Drizzle. The raw entry point
does not require Drizzle. Core workflows and replaceable service contracts remain
in `@yielded/auth`.

Applications own subject provisioning, policy, claims, delivery, and their database
connection. Managed migrations touch only the tables the configuration allocates;
install the migration Layer explicitly before starting auth.

The composed Layer covers password sign-in and management, email address verification
and changes, phone sign-in, and passkey sign-in and management with stateful sessions
on PostgreSQL and SQLite. Explicit Drizzle adapter factories cover the other workflows.
See [persistence examples](../../docs/reference/adapters.md#runnable-examples) for all
four ownership models and their current limits.
