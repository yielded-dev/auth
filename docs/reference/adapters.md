---
description: Connect Drizzle storage to your authentication service.
---

# Adapters and persistence

Choose the adapter for your database and runtime. You own the tables and migrations;
the adapter maps them to Yielded Auth's storage services.

## Connect password storage

For SQLite on Bun, create the Drizzle client and provide the resulting service:

```ts [auth-persistence.ts]
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Effect, Layer } from "effect";
import { makePasswordPersistenceServices } from "@yielded/auth/DrizzleSqliteBun";
import { PasswordPersistence } from "@yielded/auth/Password";

import { passwordMapping } from "./schema";

export const PasswordPersistenceLive = Layer.unwrap(
  Effect.gen(function* () {
    const db = yield* Drizzle.makeWithDefaults({});
    const services = yield* makePasswordPersistenceServices(db, passwordMapping);

    return Layer.succeed(PasswordPersistence, services.passwordPersistence);
  }),
).pipe(Layer.provide(SqliteClient.layer({ filename: "auth.sqlite" })));
```

`passwordMapping` maps your account, identifier, credential, revision, attempt,
and receipt tables. It is a `PasswordPersistenceMapping` from `@yielded/auth/Drizzle`.
Supply `LifecycleHooks` and your other account/session Layers at the composition root.

## Compose the application Layer

```ts [auth-live.ts]
import { Layer } from "effect";
import { Auth } from "@yielded/auth";

import { AppAuth } from "./auth";
import { AccountsLive } from "./auth-accounts";
import { requestBinding } from "./auth-config";
import { PasswordPersistenceLive } from "./auth-persistence";
import { SessionPersistenceLive } from "./session-persistence";

export const AuthDependencies = Layer.mergeAll(
  Auth.RequestBindingConfig.layer(requestBinding),
  PasswordPersistenceLive,
  SessionPersistenceLive,
  AccountsLive,
);

export const AuthLive = AppAuth.layer.pipe(Layer.provide(AuthDependencies));
```

Provide `AuthDependencies` to `Http.layer(...)`; use `AuthLive` for direct service
composition. The `auth-*` imports are your application modules. TypeScript reports any remaining
service requirements. `Sessions.stateful(...)` on `Auth.make` configures sessions;
supply a separate session/completion Layer only when using custom session setup
such as [pending authentication](../guide/totp). Keep `Auth.AuthRequest` out of this shared Layer; supply it
for each request or use [the HTTP adapter](../guide/http-and-client).

## Choose a driver

| Database / runtime    | Direct import                     |
| --------------------- | --------------------------------- |
| PostgreSQL            | `@yielded/auth/DrizzlePostgres`   |
| PGlite                | `@yielded/auth/DrizzlePglite`     |
| MySQL                 | `@yielded/auth/DrizzleMysql2`     |
| libSQL                | `@yielded/auth/DrizzleLibsql`     |
| SQLite on Bun         | `@yielded/auth/DrizzleSqliteBun`  |
| SQLite on Node        | `@yielded/auth/DrizzleSqliteNode` |
| SQLite WASM           | `@yielded/auth/DrizzleSqliteWasm` |
| Cloudflare D1         | `@yielded/auth/DrizzleD1`         |
| Durable Object SQLite | `@yielded/auth/DrizzleSqliteDo`   |

Install the selected driver's Effect SQL and Drizzle peers. Import it directly to
avoid loading unrelated adapters. Shared mapping types live in `@yielded/auth/Drizzle`.

## Passwords

Use `makePasswordPersistenceServices` for verification and mutation storage;
`makePasswordRegistrationServices` supplies registration authority. Reset support
also needs a proof mapping.

```text
password mutation transaction
  ├─ charge/check attempt budget
  ├─ check account + credential revisions
  ├─ update password and security revision
  └─ commit receipt
```

Use the adapter's coordinator when combining authentication with application writes.
Do not put standalone services inside an untracked raw Drizzle transaction.
Prepared intents retain admission charges even after sensitive material is erased.

## Email

`makeEmailSignInServices` performs lookup. `makeEmailRegistrationServices` and
`makeEmailAddressServices` own account creation and address changes. Address changes
consume their proof and advance security revisions in the same transaction.
Notifications run after commit; durable delivery needs an outbox.

## OAuth

Use `makeOAuthSignInServices` for durable flow and identity state. Registration
and linking have separate factories and authorities. An external provider exchange
cannot be rolled back with your database; retain the original decision and require
a fresh flow after an uncertain exchange.

## Passkeys

`makePasskeyPersistenceServices` stores ceremonies; credential, enrollment,
registration, and management services have separate factories. Completion rechecks
the challenge, relying party, account revision, and credential revision before
committing its result.

## Connected OAuth grants

`makeOAuthConnectedServices` and `makeOAuthConnectedRevocationServices` coordinate
provider grants, refresh attempts, and revocation. Keep the durable grant identity
and refresh claim so another worker cannot repeat an uncertain refresh.

<details>
<summary>D1 and Durable Object transaction boundaries</summary>

D1 uses a preplanned conditional batch, not an interactive transaction. Allocate
registration IDs before the batch. Do not replay a caller-owned mutation after an
ambiguous response.

Durable Object SQLite callbacks inside `transactionSync` must remain synchronous.
Do verification and asynchronous work outside that callback, then recheck the
captured authority before committing.

</details>

See [integration references](../guide/examples#database-adapters) for concrete
table definitions and mappings.
