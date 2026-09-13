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

```ts [auth-dependencies.ts]
import { Layer } from "effect";
import { Auth } from "@yielded/auth";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";

import { AccountsLive } from "./auth-accounts";
import { requestBinding } from "./auth-config";
import { SessionPersistenceLive } from "./session-persistence";

export const AuthDependencies = Layer.mergeAll(
  Auth.RequestBindingConfig.layer(requestBinding),
  SessionPersistenceLive,
  AccountsLive,
  layerWebCrypto,
  LifecycleHooks.empty,
);
```

`AccountsLive` supplies `Sessions.AuthenticationAuthority`: it checks the current
account and credential revisions and decides which factors are required.
`SessionPersistenceLive` supplies the bound `AppAuth.sessions.StatefulSessionPersistence`
and `AppAuth.sessions.SessionRepository`. Both Layers use your account model;
neither has an automatic default.

Add the method's Layers, such as `PasswordLive` from the [password guide](../guide/passwords#supply-the-services):

```ts [auth-routes.ts]
import { Layer } from "effect";
import { Http } from "@yielded/auth";

import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { PasswordLive } from "./password-live";

export const AuthRoutes = Http.layer(AppAuth, { origin: "https://app.example.com" }).pipe(
  Layer.provide(PasswordLive),
  Layer.provide(AuthDependencies),
);
```

The relative imports are your application modules. Use `AppAuth.layer` in place
of `Http.layer(...)` for local service composition. TypeScript reports any remaining
requirements. `Sessions.stateful(...)` on `Auth.make` configures sessions;
supply a separate session/completion Layer only when using custom session setup
such as [pending authentication](../guide/totp). Keep `Auth.AuthRequest` out of this shared Layer; supply it
for each request or use [the HTTP adapter](../guide/http-and-client).

### Defaults and required configuration

`Auth.make` wires the selected methods, session implementation, Web Crypto, and
empty lifecycle hooks. Password hashing also has a bounded default implementation.
Separately constructed adapters need crypto and hooks supplied explicitly,
as above. You supply storage mappings, account authority, claims, delivery, and
secret keys. Adapters provide implementations; they are not installed automatically.

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

## Phone

Wrap the adapter's phone services in one Layer:

```ts [auth-persistence.ts]
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Effect, Layer } from "effect";
import { phonePersistenceLayer } from "@yielded/auth/Drizzle";
import {
  makePhonePersistenceServices,
  makeProofPersistenceServices,
} from "@yielded/auth/DrizzleSqliteBun";
import { ProofPersistence } from "@yielded/auth/Proofs";

import { DatabaseLive } from "./database";
import { phoneMapping, proofMapping } from "./schema";

export const PhonePersistenceLive = phonePersistenceLayer(
  Effect.gen(function* () {
    const db = yield* Drizzle.makeWithDefaults({});
    return yield* makePhonePersistenceServices(db, phoneMapping);
  }),
).pipe(Layer.provide(DatabaseLive));

export const ProofPersistenceLive = Layer.effect(
  ProofPersistence,
  Effect.gen(function* () {
    const db = yield* Drizzle.makeWithDefaults({});
    const services = yield* makeProofPersistenceServices(db, proofMapping);
    return services.proofPersistence;
  }),
).pipe(Layer.provide(DatabaseLive));
```

`DatabaseLive` is your configured Effect SQL client Layer. The phone Layer supplies
`PhonePersistence`, `PhoneAdmission`, and `PhoneSignInTargets`; the proof Layer
stores challenges, consumption, and rate limits. You provide table mappings and
migrations. See the [SQLite example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts)
for the full composition.

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
