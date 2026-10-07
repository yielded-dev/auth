# @yielded/auth-persistence-drizzle

Drizzle bindings, table mappings, and migration helpers for Yielded Auth. This
package implements native Drizzle queries for the shared storage contracts and
workflow policy in `@yielded/auth-persistence`.

Import mapping helpers from the root and a driver from its explicit module, such
as `/Postgres` or `/SqliteBun`. Install `drizzle-orm` and the corresponding Effect
SQL driver. Supply Effect `Crypto` to persistence construction and transaction
coordinators. Composed drivers expose `AuthPersistence`; explicit driver modules
also expose lower-level factories.

Drizzle RC4 does not yet support the current stable Effect APIs required by Yielded
Auth. Bun consumers need the temporary
[@yielded/drizzle-effect-v4-patch](../drizzle-effect-v4-patch/README.md) until they
upgrade to a compatible upstream Drizzle release.

Applications own subjects, policy, claims, delivery, and database connections.
Drizzle Kit generates migrations from managed or application-declared tables.
Provide `AuthPersistence.migrationsLayer({ migrationsFolder })` explicitly to
apply those files before starting auth.

SQLite/D1 and PostgreSQL driver modules also expose `OAuthProxyPersistence` for
[callback proxy storage](../../docs/src/content/docs/reference/oauth.md#callback-server).

Durable Object SQLite uses Effect SQL’s asynchronous transaction owner. Use
`SqliteDo.databaseLayer` or `SqliteDo.makeDatabase(existingDrizzle)` so cryptography
can suspend inside the owned transaction; arbitrary raw Drizzle outer
transactions are unsupported.

See the [adapter guide](../../docs/src/content/docs/reference/adapters.md) for transaction ownership,
runtime constraints, and runnable examples.
