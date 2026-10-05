---
title: Adapters and persistence
description: Choose managed storage, your own SQL schema, or custom Effect services.
---

`@yielded/auth` owns workflows and service contracts. Its only third-party runtime
dependency is Effect; first-party crypto and OAuth packages supply the primitives.
`@yielded/auth-persistence` supplies direct Effect SQL persistence and shared storage
contracts. `@yielded/auth-persistence-drizzle` adds Drizzle bindings, managed tables,
and migration helpers. Applications choose their adapter and own customer
provisioning, policy, claims, delivery, and database connections.

Install the Drizzle companion, `drizzle-orm`, and an explicit Effect SQL driver when
using Drizzle. Direct SQL applications need only the default persistence package and
their driver.

## Runnable examples

[Database and backend choices](../guide/storage) explains the three storage options. The [four account apps](../guide/examples#run-an-account-app)
show managed Drizzle tables, an application-owned Drizzle schema, direct Effect
SQL, and custom services. Start there to compare ownership and composition, or
[run an example](../guide/examples#run-an-account-app) for the complete setup.
This reference covers the persistence APIs and their transaction requirements.

## Compose persistence once

Choose a named facade for your backend:

```ts
import { AuthPersistence } from "@yielded/auth-persistence-drizzle/SqliteBun";
// Direct Effect SQL: import { AuthPersistence } from "@yielded/auth-persistence";
```

Bind it to the Auth definition and map the existing customer table:

```ts title="apps/server/schema.ts"
import { AuthPersistence } from "@yielded/auth-persistence-drizzle/SqliteBun";
import { Schema as AuthSchema } from "@yielded/auth";
import { Effect } from "effect";
import { AppAuth, requirement } from "./auth";
import { customers } from "./customers";

export const Persistence = AuthPersistence.make(AppAuth);
export const storage = Persistence.managed({
  prefix: "app_auth",
  subjects: {
    table: customers,
    id: "id",
    status: "enabled",
    activeValue: true,
    securityRevision: "securityRevision",
    idCodec: AuthSchema.SubjectId,
    requirements: () => Effect.succeed(requirement),
  },
});
export const authSchema = storage.schema;
```

`authSchema` contains ordinary Drizzle tables before any Layer starts. Only enabled
capabilities allocate storage; shared proof storage is configured once. Use
`Persistence.map({ subjects, tables })` when your application declares all tables.
`managed` also accepts table overrides. Keep `prefix` explicit and stable; it is a
physical table identifier, not a per-process random value. Both direct Effect SQL
and Drizzle `managed` require it. For an existing database that used a generated prefix,
pass that exact prefix from its deployed table names; a different prefix selects
different tables and does not migrate credentials. Export each enabled table from
`authSchema` as a named export so Drizzle Kit discovers it; the
[managed schema](https://github.com/yielded-dev/auth/blob/main/examples/persistence-drizzle-managed/src/schema.ts)
shows the complete exports. Both Drizzle examples use Drizzle Kit:

```ts title="apps/server/drizzle.config.ts"
import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  schema: ["./customers.ts", "./schema.ts"],
  out: "./drizzle",
});
```

Generate SQL after changing the schema, review it, and commit the SQL and snapshot.
The examples expose `vp run db:generate --name=describe_change` and `vp run db:migrate`
from their directories. The latter uses the same migration Layer as startup:

```ts title="apps/server/auth-live.ts"
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { AuthPersistence } from "@yielded/auth-persistence-drizzle/SqliteBun";
import { WebCrypto } from "@yielded/auth";
import { Layer } from "effect";
import { AppAuth } from "./auth";
import { ApplicationLive } from "./application"; // claims, keys, delivery, hashing
import { Persistence, storage } from "./schema";

const DatabaseLive = SqliteClient.layer({ filename: "auth.sqlite" });
const ConfigLive = Persistence.Config.layer(storage);
const DatabaseReady = AuthPersistence.migrationsLayer({
  migrationsFolder: new URL("./drizzle/", import.meta.url).pathname,
}).pipe(Layer.provideMerge(ConfigLive), Layer.provideMerge(DatabaseLive));
export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(Persistence.layer),
  Layer.provide(ApplicationLive),
  Layer.provide(DatabaseReady),
  Layer.provide(WebCrypto.layerCryptoWeb),
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

For SQLite on Bun, supply the driver database Layer and your table mapping:

```ts title="apps/server/auth-persistence.ts"
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { Effect, Layer } from "effect";
import {
  databaseLayer,
  makePasswordPersistenceServices,
} from "@yielded/auth-persistence-drizzle/SqliteBun";
import { Password } from "@yielded/auth";

import { passwordMapping } from "./schema";

export const PasswordPersistenceLive = Layer.effect(
  Password.PasswordPersistence,
  Effect.map(
    makePasswordPersistenceServices(passwordMapping),
    (services) => services.passwordPersistence,
  ),
).pipe(
  Layer.provide(databaseLayer),
  Layer.provide(SqliteClient.layer({ filename: "auth.sqlite" })),
);
```

`passwordMapping` maps your account, identifier, credential, revision, attempt,
and receipt tables. It is a `PasswordPersistenceMapping` from `@yielded/auth-persistence-drizzle`.
Supply `LifecycleHooks` and your other account/session Layers at the composition root.
Driver factories and transaction coordinators declare `Database` and Effect
`Crypto` requirements at acquisition. Provide your platform's Crypto Layer to
the persistence Layer itself and to Auth at your composition root. SHA digests and
entropy use Effect Crypto and may suspend.

Use `databaseLayer` to acquire `Database` from the platform SQL client. Most drivers
also accept a native database through `Layer.succeed(Database, db)`. Durable Object
SQLite instead exposes `DatabaseValue`: `databaseLayer` builds this projection,
or `makeDatabase(existingDrizzle)` adapts an existing database while preserving
its query configuration. Its SQL client must be configured with Durable Object
`storage`. Transactions belong to Effect SQL and support asynchronous Effects.

Explicit Drizzle factories and transaction coordinators check mapped unique keys
against the captured database's catalog during acquisition. Apply migrations before
building these Layers; a Drizzle declaration does not install a constraint. Permit
catalog reads on PostgreSQL, MySQL, and SQLite, and reacquire services after schema
changes. These checks cover usable, unconditional unique keys; application predicates
and column codecs remain application contracts. Retain the acquired persistence Layer
at the application composition root so requests reuse its schema validation and
configuration. Operations still check current authority inside their transactions.

## Compose the application Layer

```ts title="apps/server/auth-dependencies.ts"
import { Layer } from "effect";
import { Auth, Hooks, Proofs } from "@yielded/auth";
import { CryptoLive } from "./crypto-live";

import { AccountsLive } from "./auth-accounts";
import { requestBinding, proofKeys } from "./auth-config";
import { SessionPersistenceLive } from "./session-persistence";

export const AuthDependencies = Layer.mergeAll(
  Auth.RequestBindingConfig.layer(requestBinding),
  Proofs.ProofKeys.layer(proofKeys),
  SessionPersistenceLive,
  AccountsLive,
  Hooks.LifecycleHooks.empty,
).pipe(Layer.provideMerge(CryptoLive));
```

[`CryptoLive`](./crypto#use-with-auth) is the shared application crypto Layer.
`proofKeys` is your secret-managed numeric-code keyring. Retain old key IDs until
their proofs expire.

`AccountsLive` supplies `Sessions.AuthenticationAuthority`: it checks the current
account and credential revisions and decides which factors are required.
`SessionPersistenceLive` supplies the bound `AppAuth.sessions.StatefulSessionPersistence`
and `AppAuth.sessions.SessionRepository`. Both Layers use your account model;
neither has an automatic default.

Add the method's Layers, such as `PasswordLive` from the [password guide](../guide/passwords#supply-the-services):

```ts title="apps/server/auth-routes.ts"
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

`Auth.make` wires the selected methods, session implementation, and empty lifecycle
hooks. Supply the application's [crypto Layer](./crypto#use-with-auth) and
`PasswordHashing` explicitly, for example with the bounded
[`Password.PasswordHashing.layer()`](../guide/passwords#supply-the-services).
Adapter factories expose their crypto and hook requirements; supply them as above.
Layer helpers may supply empty hooks, while crypto remains an application choice.
You supply storage mappings, account authority, claims, delivery, and secret keys.
Adapters provide implementations; they are not installed automatically.

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

Adapter authors can reuse the canonical row codecs when composing explicit services:

```ts
import { makeStorageMappings } from "@yielded/auth-persistence/Adapter";
import { Effect } from "effect";

const proofMapping = Effect.gen(function* () {
  const mappings = yield* makeStorageMappings(storage);
  return mappings.proofs();
});
```

Mapping construction requires Effect `Crypto`; provide it at the calling Layer.
The layout must include each requested mapping's role tables. These are shared
mapping types: the adapter still supplies typed table handles and, for D1, its
engine clock and atomic commit predicates. Refine authority policy only for the
intended proof purpose; the composed Layer's defaults remain unchanged.

Use the Effect SQL peer ranges declared by the adapter package and keep the driver
aligned with `effect`. The native PostgreSQL driver accepts one
statement per query, decodes `int8` as `bigint`, timestamps as `Date`, and `bytea`
as `Uint8Array`. Match application-owned column codecs to these values; use
`sql.json` for JSON parameters. Set `prepare: false` for poolers that cannot retain
prepared statements between queries.

Drizzle RC4's Effect integration still uses APIs removed from the current stable
Effect release. Until Drizzle ships a compatible release, apply this temporary
patch to use it with Yielded Auth. In a Bun app, install your dependencies and run
this from the workspace that depends on Drizzle:

```sh
bun add drizzle-orm@1.0.0-rc.4
bunx @yielded/drizzle-effect-v4-patch@beta patch
```

The CLI updates Drizzle's declarations, error classes, and schema helper, then runs `bun install`.
Commit the generated patch, root manifest, and lockfile. It accepts only the
released Drizzle RC4 version, which the adapter supports. See the
[patch package](https://github.com/yielded-dev/auth/tree/main/packages/drizzle-effect-v4-patch)
for the exact supported build. Run the same command with `unpatch` before upgrading
to a compatible upstream release. No lifecycle hook is required.

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
`makeEmailAddressServices` own account creation and address changes.

For explicit composition over an existing storage layout, start from
`yield* makeStorageMappings(storage)` and use its `.emails()` and `.proofs()` factories.
Supply the raw registration mapping's provisioning, receipt table, and inspection policy.

Atomic email registration provisions a fresh subject after mailbox proof. Its
`inspect` policy and proof authority's `identifier.isCurrent` must admit absent or
active-unverified targets to permit reclamation; D1's `d1CurrentCondition` must
express the same rule at batch commit. Scope this permission to
`email-code-registration`. The adapter rechecks the old owner, binding revision,
unverified timestamp, and subject security revision, then updates the identifier's
mapped `subjectId`, `verifiedAt`, and `bindingRevision` in place. Other identifier
columns stay unchanged and the resulting row must satisfy `isCurrent`.

Reclamation advances the previous subject's security revision without moving its
credentials or application data. Identifier eligibility is separate from the prior
subject's status: a disabled subject stays disabled. Sessions and pending authentication must consult
that revision for immediate invalidation; purely stateless sessions retain their
documented lifetime. Provisioning, reclamation, receipt, and proof consumption share
one transaction or D1 batch. Verified addresses cannot be reclaimed. Pending-mode
registration only records a provisioning intent; the application owns its eventual
binding transition. Compose this guest workflow explicitly as shown in
[mailbox registration](../guide/codes#register-a-mailbox-owner).

Address changes consume their proof and advance security revisions in the same transaction.
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

Standalone credential lookup uses one SELECT when mapped references share compatible
SQL types and ID encodings. It opens no transaction. Custom codecs that transform IDs
outside SQL require additional mapped reads. Lookup is advisory; authentication
mutations recheck live ownership and authority before committing.

## Phone

For sign-in with managed or mapped storage, the composed Layer above supplies
phone and proof services together. For number lifecycle operations or specialized
row mappings, wrap the explicit adapter services:

<!-- #region phone-layers -->

```ts title="apps/server/auth-persistence.ts"
import { Effect, Layer } from "effect";
import { phonePersistenceLayer } from "@yielded/auth-persistence-drizzle";
import {
  databaseLayer,
  makePhonePersistenceServices,
  makeProofPersistenceServices,
} from "@yielded/auth-persistence-drizzle/SqliteBun";
import { Proofs } from "@yielded/auth";

import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { CryptoLive } from "./crypto-live";
import { phoneMapping, proofMapping } from "./schema";

const DatabaseLive = databaseLayer.pipe(
  Layer.provide(SqliteClient.layer({ filename: "auth.sqlite" })),
);

export const PhonePersistenceLive = phonePersistenceLayer(
  makePhonePersistenceServices(phoneMapping),
).pipe(Layer.provide([DatabaseLive, CryptoLive]));

export const ProofPersistenceLive = Layer.effect(
  Proofs.ProofPersistence,
  Effect.gen(function* () {
    const services = yield* makeProofPersistenceServices(proofMapping);
    return services.proofPersistence;
  }),
).pipe(Layer.provide([DatabaseLive, CryptoLive]));
```

The database connection above uses SQLite on Bun. The phone Layer supplies
`PhonePersistence`, `PhoneAdmission`, and `PhoneSignInTargets`, with empty hook
defaults. Both persistence Layers use the application's explicit `CryptoLive`.
The proof Layer stores challenges, consumption, and rate limits. Sign-in uses
lookup and admission; number-management operations
also use `PhonePersistence`. You provide table mappings and
migrations. See the [SQLite example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts)
for the table definitions and mappings.

<!-- #endregion phone-layers -->

## Connected OAuth grants

`makeOAuthConnectedServices` and `makeOAuthConnectedRevocationServices` coordinate
provider grants, refresh attempts, and revocation. Keep the durable grant identity
and refresh claim so another worker cannot repeat an uncertain refresh.

For `OAuth.make({ access: profile })`, use those same connected services alongside
`makeOAuthSignInServices`. Map `signIn.credential` and `signIn.flow` to the shared
sign-in tables and provide `flow.encodeSignIn`; the connected flow’s subject column
must allow NULL until identity resolution. The
[OAuth storage example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/oauth-storage.ts)
shows the application-owned schema and authority.

<details>
<summary>D1 and Durable Object transaction boundaries</summary>

D1 uses a preplanned conditional batch, not an interactive transaction. Allocate
registration IDs before the batch. Do not replay a caller-owned mutation after an
ambiguous response.

Durable Object SQLite uses the captured Effect SQL client's asynchronous
`storage.transaction` boundary. Use `SqliteDo.databaseLayer` or
`SqliteDo.makeDatabase(existingDrizzle)` and the adapter's transaction coordinators;
crypto Effects may suspend inside that owned transaction. An arbitrary raw Drizzle
outer transaction, including its `transactionSync` callbacks, is unsupported.
No synchronous crypto implementation or `Effect.runSync` bridge is required.

Compatible scalar mappings use grouped cleanup reads and writes, with atomic checks
after application work and database triggers. Groups split at the driver's statement
and bound-data limits. Custom SQL encoders, collation aliases, and staged D1 writes
can require additional statements; a page size alone does not determine its cost.
Budget every statement and transaction-control call as a database roundtrip.
Direct Effect SQL uses SQLite limits that also fit Durable Objects.

</details>

See [integration references](../guide/examples#database-adapters) for concrete
table definitions and mappings.
