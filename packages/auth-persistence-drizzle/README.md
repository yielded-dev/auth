# @yielded/auth-persistence-drizzle

Drizzle bindings, table mappings, and migration helpers for Yielded Auth. This
package uses the shared storage contracts and SQL kernels in
`@yielded/auth-persistence`.

Import mapping helpers from the root and a driver from its explicit module, such
as `/Postgres` or `/SqliteBun`. Install `drizzle-orm` and the corresponding Effect
SQL driver. Each driver exposes `AuthPersistence` and the lower-level factories.

Applications own subjects, policy, claims, delivery, and database connections.
Drizzle Kit generates migrations from managed or application-declared tables.
Provide `AuthPersistence.migrationsLayer({ migrationsFolder })` explicitly to
apply those files before starting auth.

See the [adapter guide](../../docs/src/content/docs/reference/adapters.md) for transaction ownership,
runtime constraints, and runnable examples.
