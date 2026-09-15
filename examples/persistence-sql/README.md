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
