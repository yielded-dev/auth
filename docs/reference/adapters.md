---
description: Choose managed storage, your own SQL schema, or custom Effect services.
---

# Adapters and persistence

`@yielded/auth` owns workflows and service contracts and depends only on Effect.
`@yielded/auth-persistence` supplies direct Effect SQL persistence and shared storage
contracts. `@yielded/auth-persistence-drizzle` adds Drizzle bindings, managed tables,
and migration helpers. Applications choose their adapter and own customer
provisioning, policy, claims, delivery, and database connections.

Install the Drizzle companion, `drizzle-orm`, and an explicit Effect SQL driver when
using Drizzle. Direct SQL applications need only the default persistence package and
their driver.

## Runnable examples

| Example                                                                                               | Schema and migration owner                 | Backend                          |
| ----------------------------------------------------------------------------------------------------- | ------------------------------------------ | -------------------------------- |
| [Managed Drizzle](https://github.com/yielded-dev/auth/tree/main/examples/persistence-drizzle-managed) | Application customers; library auth tables | SQLite                           |
| [Custom Drizzle](https://github.com/yielded-dev/auth/tree/main/examples/persistence-drizzle-custom)   | Application                                | SQLite                           |
| [Effect SQL](https://github.com/yielded-dev/auth/tree/main/examples/persistence-sql)                  | Application                                | SQLite or PostgreSQL, no Drizzle |
| [Custom services](https://github.com/yielded-dev/auth/tree/main/examples/persistence-custom)          | Application implementations                | Local file store, no SQL         |

All four examples are account apps with registration,
email verification, passkey enrollment and sign-in, password recovery, and Cloudflare
delivery. They keep separate data across restarts, on ports 4181–4184 respectively.
All use application-owned subjects and custom hashing. The custom-service example
also replaces registration planning and implements username-or-email sign-in.
The three SQL examples import the same
[`AuthApi`](https://github.com/yielded-dev/auth/blob/main/examples/shared/account/contract.ts)
and [`AppAuth`](https://github.com/yielded-dev/auth/blob/main/examples/shared/account/auth.ts).
Their `live.ts` files provide different persistence and account Layers to that definition.
The custom-service example extends the shared fields and actions with username inputs
and binds registration and sign-in to its `AccountMethods` service. Email, recovery,
passkey, and session contracts retain the common definitions.
Hashing, Cloudflare delivery, forms, styles, and Atom workflows also live in
[`examples/shared/account`](https://github.com/yielded-dev/auth/tree/main/examples/shared/account).
Each app creates its own client and runtime.
The custom app's single-writer file store provides the public persistence services directly;
see its [Layer wiring](https://github.com/yielded-dev/auth/blob/main/examples/persistence-custom/src/live.ts)
and [method replacement](https://github.com/yielded-dev/auth/blob/main/examples/persistence-custom/src/password-methods.ts).

## Compose persistence once

Choose a named facade for your backend:

```ts
import { AuthPersistence } from "@yielded/auth-persistence-drizzle/SqliteBun";
// Direct Effect SQL: import { AuthPersistence } from "@yielded/auth-persistence";
```

Bind it to the Auth definition and map the existing customer table:

```ts [schema.ts]
import { AuthPersistence } from "@yielded/auth-persistence-drizzle/SqliteBun";
import { SubjectId } from "@yielded/auth/Schema";
import { Effect } from "effect";
import { AppAuth, requirement } from "./auth";
import { customers } from "./customers";

export const Persistence = AuthPersistence.make(AppAuth);
export const storage = Persistence.managed({
  subjects: {
    table: customers,
    id: "id",
    status: "enabled",
    activeValue: true,
    securityRevision: "securityRevision",
    idCodec: SubjectId,
    requirements: () => Effect.succeed(requirement),
  },
});
export const authSchema = storage.schema;
```

`authSchema` contains ordinary Drizzle tables before any Layer starts. Only enabled
capabilities allocate storage; shared proof storage is configured once. Use
`Persistence.map({ subjects, tables })` when your application declares all tables.
`managed` also accepts table overrides. Export each enabled table from `authSchema`
as a named export so Drizzle Kit discovers it; the
[managed schema](https://github.com/yielded-dev/auth/blob/main/examples/persistence-drizzle-managed/src/schema.ts)
shows the complete exports. Both Drizzle examples use Drizzle Kit:

```ts [drizzle.config.ts]
import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  schema: ["./src/customers.ts", "./src/schema.ts"],
  out: "./drizzle",
});
```

Generate SQL after changing the schema, review it, and commit the SQL and snapshot.
The examples expose `vp run db:generate --name=describe_change` and `vp run db:migrate`
from their directories. The latter uses the same migration Layer as startup:

```ts [auth-live.ts]
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { AuthPersistence } from "@yielded/auth-persistence-drizzle/SqliteBun";
import { Layer } from "effect";
import { AppAuth } from "./auth";
import { ApplicationLive } from "./application"; // claims, keys, delivery, hashing
import { Persistence, storage } from "./schema";

const DatabaseLive = SqliteClient.layer({ filename: "auth.sqlite" });
const ConfigLive = Persistence.Config.layer(storage);
const DatabaseReady = AuthPersistence.migrationsLayer({
  migrationsFolder: new URL("../drizzle/", import.meta.url).pathname,
}).pipe(Layer.provideMerge(ConfigLive), Layer.provideMerge(DatabaseLive));
export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(Persistence.layer),
  Layer.provide(ApplicationLive),
  Layer.provide(DatabaseReady),
);
```

Drizzle owns the migration journal and applies pending files transactionally.
The generated migrations include the customer table and whichever auth tables the
schema exports. Schema changes, including removal of a capability's tables, require
a reviewed migration; startup only applies committed files. A failed migration stops
auth startup. The persistence Layer checks physical columns and unique keys before
serving auth. File-based drivers load the migration folder only when the Layer starts;
SQLite WASM accepts Drizzle's `migrations` map instead of a folder. Direct Effect SQL
applications supply their own migrations, as shown in the raw SQL example.

The composed API supports password sign-in and management, email address verification
and changes, phone sign-in, and stateful sessions. Email storage permits one verified
address per subject and email module; changing it retires the source address.
It uses canonical logical column names and text auth IDs;
subject ID codecs and order-preserving timestamp codecs remain application-owned.
Other workflows and specialized layouts use the explicit adapters below or the
core service contracts. Those contracts do not require Effect SQL or particular
physical tables. The default schema is one implementation of the storage roles.

Direct SQL and Drizzle composition support passkey sign-in and management on PostgreSQL
and SQLite.
Enabling these strategies adds their storage and a `PasskeyConfig` requirement; the
application still supplies action authorization, claims, and the protocol verifier.
Composed passkey tables use integer milliseconds. Custom passkey timestamps use
the explicit adapters or core service ports.
The layer initializes module policy and admission records. Increment the strategy's
`policy.generation` when changing a stored passkey policy; disabled modules stay disabled.
Removal preserves a remaining password or user-verified passkey that independently
meets current sign-in requirements. More involved factor combinations use an explicit
`write.policy.remainingSignIn` predicate, returned in Effect from the captured subject row.

With password registration enabled, also supply `Persistence.Provisioning`:

```ts
const ProvisioningLive = Layer.succeed(Persistence.Provisioning, {
  password: createCustomer, // ({ registration, identifier }) => Effect<SubjectId, PasswordUnavailable>
});
const PersistenceLive = Persistence.layer.pipe(Layer.provide(ProvisioningLive));
```

`createCustomer` inserts only the application subject, allocating its ID and initial
security revision. It runs inside the library's SQL transaction: use the same Effect
SQL client, including Drizzle over it. Identifier, password, and receipt writes commit
with that insert. Do not send email or open a separate transaction in this callback.
Replays suppress creation and never overwrite or recover another request's password.
See the [managed example's wiring](https://github.com/yielded-dev/auth/blob/main/examples/persistence-drizzle-managed/src/live.ts).
`subjects.actionRequirements` can supply a distinct recovery or credential-change
policy; it defaults to `subjects.requirements`.

Standalone operations retain their transaction, revision, proof-consumption,
and receipt checks. They reject unrelated ambient transactions. Combine protected
application writes through an explicit transaction adapter; an unknown commit
outcome does not authorize issuing another credential or repeating delivery.

## Connect password storage

For SQLite on Bun, create the Drizzle client and provide the resulting service:

```ts [auth-persistence.ts]
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Effect, Layer } from "effect";
import { makePasswordPersistenceServices } from "@yielded/auth-persistence-drizzle/SqliteBun";
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
and receipt tables. It is a `PasswordPersistenceMapping` from `@yielded/auth-persistence-drizzle`.
Supply `LifecycleHooks` and your other account/session Layers at the composition root.

## Compose the application Layer

```ts [auth-dependencies.ts]
import { Layer } from "effect";
import { Auth } from "@yielded/auth";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import { ProofKeys } from "@yielded/auth/Proofs";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";

import { AccountsLive } from "./auth-accounts";
import { requestBinding, proofKeys } from "./auth-config";
import { SessionPersistenceLive } from "./session-persistence";

export const AuthDependencies = Layer.mergeAll(
  Auth.RequestBindingConfig.layer(requestBinding),
  ProofKeys.layer(proofKeys),
  SessionPersistenceLive,
  AccountsLive,
  layerWebCrypto,
  LifecycleHooks.empty,
);
```

`proofKeys` is your secret-managed numeric-code keyring. Retain old key IDs until
their proofs expire.

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
empty lifecycle hooks. Supply `PasswordHashing` explicitly, for example with the
bounded [`@yielded/auth-crypto/Password` Layer](../guide/passwords#supply-the-services).
Adapter factories expose their crypto and hook requirements; supply them as above
or use a Layer helper that installs defaults. You supply storage mappings, account authority, claims, delivery, and
secret keys. Adapters provide implementations; they are not installed automatically.

## Choose a driver

| Database / runtime    | Direct import                                  |
| --------------------- | ---------------------------------------------- |
| PostgreSQL            | `@yielded/auth-persistence-drizzle/Postgres`   |
| PGlite                | `@yielded/auth-persistence-drizzle/Pglite`     |
| MySQL                 | `@yielded/auth-persistence-drizzle/Mysql2`     |
| libSQL                | `@yielded/auth-persistence-drizzle/Libsql`     |
| SQLite on Bun         | `@yielded/auth-persistence-drizzle/SqliteBun`  |
| SQLite on Node        | `@yielded/auth-persistence-drizzle/SqliteNode` |
| SQLite WASM           | `@yielded/auth-persistence-drizzle/SqliteWasm` |
| Cloudflare D1         | `@yielded/auth-persistence-drizzle/D1`         |
| Durable Object SQLite | `@yielded/auth-persistence-drizzle/SqliteDo`   |

Install the selected driver's Effect SQL and Drizzle peers. Import it directly to
avoid loading unrelated adapters. Shared mapping types live in `@yielded/auth-persistence-drizzle`.

Effect SQL peers must be rc.117 or newer. The native PostgreSQL driver accepts one
statement per query, decodes `int8` as `bigint`, timestamps as `Date`, and `bytea`
as `Uint8Array`. Match application-owned column codecs to these values; use
`sql.json` for JSON parameters. Set `prepare: false` for poolers that cannot retain
prepared statements between queries.

Standalone libSQL operations reject any ambient libSQL transaction, including one
belonging to another client. Use the explicit transaction coordinators when
application writes and auth changes must share a commit.

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
Confirming an existing unverified address bound to the same subject preserves its
security revision and sessions; the completion result omits `invalidation`. The
adapter captures and rechecks the identifier's binding revision. Application policy
may authorize this confirmation with a valid session; adding or replacing an address
still requires recent authentication. Reload mutable application claims on session
reads when the UI needs to reflect verification immediately.
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
committing its result. Enrollment inserts the credential and shared factor atomically
while preserving the subject security revision and existing sessions. Removal bumps
the revision and applies the configured session invalidation in the same transaction.

## Phone

For sign-in with managed or mapped storage, the composed Layer above supplies
phone and proof services together. For number lifecycle operations or specialized
row mappings, wrap the explicit adapter services:

<!-- #region phone-layers -->

```ts [auth-persistence.ts]
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Effect, Layer } from "effect";
import { phonePersistenceLayer } from "@yielded/auth-persistence-drizzle";
import {
  makePhonePersistenceServices,
  makeProofPersistenceServices,
} from "@yielded/auth-persistence-drizzle/SqliteBun";
import { ProofPersistence } from "@yielded/auth/Proofs";

import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { phoneMapping, proofMapping } from "./schema";

const DatabaseLive = SqliteClient.layer({ filename: "auth.sqlite" });

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

The database connection above uses SQLite on Bun. The phone Layer supplies
`PhonePersistence`, `PhoneAdmission`, and `PhoneSignInTargets`, with overridable
Web Crypto and empty hook defaults. The proof Layer stores challenges, consumption,
and rate limits. Sign-in uses lookup and admission; number-management operations
also use `PhonePersistence`. You provide table mappings and
migrations. See the [SQLite example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts)
for the table definitions and mappings.

<!-- #endregion phone-layers -->

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
