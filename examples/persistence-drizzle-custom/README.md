# Drizzle with application-owned schema and migrations

The account app from the managed example, with application-declared Drizzle tables
and versioned SQL migrations. It supports registration, Cloudflare email verification,
password recovery, and adding and signing in with passkeys.

Copy `.env.example` to `.env` and fill in `CLOUDFLARE_ACCOUNT_ID` and
`CLOUDFLARE_API_TOKEN`. `AUTH_EMAIL_FROM` defaults to `hello@effect-agent.com`.

```sh
vp -C examples/persistence-drizzle-custom run start
```

Open http://localhost:4182 and create an account. Each example has its own database;
this one's accounts, sessions, proofs, and passkeys persist in `.data/auth.sqlite`.
Private proof and request-binding keys persist in `.data/keys.json`.

[tables.ts](src/tables.ts) and [passkey-tables.ts](src/passkey-tables.ts) declare the
application's physical tables and columns. [schema.ts](src/schema.ts) connects them
with `Persistence.map({ subjects, tables })`. The application owns every migration
in [migrations.ts](src/migrations.ts), recorded in `customer_migrations`.
[live.ts](src/live.ts) runs those migrations before providing persistence:

```ts
const DatabaseReady = MigrationsLive.pipe(Layer.provideMerge(Persistence.Config.layer(storage)));
```

The library supplies transactional auth operations. The application supplies customer
IDs, policy, claims, delivery, and custom hashing. Email confirmation and passkey
enrollment preserve the existing session. Use `localhost:4182` consistently for passkeys.

`AUTH_DATA_DIR` selects another data directory. Removing this example's `.data`
resets only its accounts, sessions, credentials, and keys.
