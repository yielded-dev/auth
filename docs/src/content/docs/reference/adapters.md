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

[Database and backend choices](../guide/storage) explains the storage options. The [four account apps](../guide/examples#run-an-account-app)
show managed Drizzle tables, an application-owned Drizzle schema, direct Effect
SQL, and custom services. Start there to compare ownership and composition, or
[run an example](../guide/examples#run-an-account-app) for the complete setup.
This reference covers the persistence APIs and their transaction requirements.

## In-memory testing

`Testing.layer(auth, options)` from `@yielded/auth-persistence/Testing` replaces
password and session persistence in tests. Start with the
[setup guide](../guide/storage#in-memory-tests) or [consumer test](https://github.com/yielded-dev/auth/blob/main/examples/auth/test/in-memory.test.ts).

| Configuration     | Behavior                                                                                                                                                                          |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`            | One sign-in-only `Password.make()` strategy and `Sessions.stateful()`. Other configurations fail acquisition with `PersistenceConfigurationError`.                                |
| `subjects`        | Each seed has `subjectId`, `email`, a redacted `password`, and optional `active` (default `true`). Duplicate IDs or normalized emails fail acquisition. Emails remain unverified. |
| `requirement`     | Required application `AuthenticationRequirement`; no test default.                                                                                                                |
| `PasswordHashing` | Required Layer dependency. Hashes seed passwords without text normalization. `Testing.services()` supplies this and Effect `Crypto`; claims remain application-owned.             |
| Clock             | Captured at acquisition. Effect's `TestClock` controls expiry directly.                                                                                                           |

Supported session operations are issuance, verification, renewal, listing,
revocation, and sign-out. Renewal invalidates the previous credential; retrying
with it fails. Sign-in creates a new session on each successful call.
Password management, pending authentication, handoff, signed-session approval,
and ambient transaction composition are unsupported and fail explicitly.

Separate acquisitions have independent state; reusing a Layer within one build
shares it. State is process-local, non-durable, and discarded on scope close.
In a Worker, acquire and use it within the request or test scope. Use the actual
production adapter to verify database concurrency or recovery.

### Test services

`Testing.services(options?)` supplies Effect `Crypto` and `PasswordHashing` with
portable Argon2id at the default password cost. Provide it to the composition of
Auth and `Testing.layer` so both use the same services.

| Option or requirement | Behavior                                                                                                                                                                                                                     |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `seed`                | Optional string or number. Restarts a private random sequence per acquisition. Equal seeds and operation order reproduce credentials; use distinct seeds for independent simulated clients. Omit for secure host randomness. |
| Runtime               | Requires global WebCrypto. Missing WebCrypto fails acquisition with `PersistenceConfigurationError`.                                                                                                                         |
| Clock                 | Inherits the caller's clock. It does not install a test clock or replace Effect's `Random` service.                                                                                                                          |

For custom crypto or hashing, supply your own Layers to `Testing.layer` and Auth
instead. Promise-based test runners can use `ManagedRuntime.make(TestAuth)` and
dispose the runtime after each test.

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
auth startup. The composed persistence Layer initializes on its first storage operation,
checking physical columns and unique keys before that operation runs. Cookie-cached
and anonymous session reads perform no persistence initialization. Initialization is
shared within that Layer's scope; failures remain the operation's typed availability
error. Rebuild the Layer after migrations or an initialization failure.
File-based drivers load the migration folder only when the migration Layer starts;
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
Each challenge retains its selected relying-party profile until expiry, so rolling
configuration changes do not invalidate ceremonies already in progress.
Removal preserves a remaining password or user-verified passkey that independently
meets current sign-in requirements. More involved factor combinations use an explicit
`write.policy.remainingSignIn` predicate, returned in Effect from the captured subject row.

With password registration enabled, also supply `Persistence.Provisioning`:

```ts
const ProvisioningLive = Layer.succeed(Persistence.Provisioning, {
  password: createCustomer, // ({ requestId, registration, identifier }) => Effect<SubjectId, PasswordUnavailable>
});
const PersistenceLive = Persistence.layer.pipe(Layer.provide(ProvisioningLive));
```

`createCustomer` inserts only the application subject, allocating its ID and initial
security revision. It runs inside the library's SQL transaction: use the same Effect
SQL client, including Drizzle over it. Identifier and password writes commit with
that insert. The stable `requestId` identifies the application operation.
Do not send email or open a separate transaction in this callback.
An occupied identifier suppresses creation; retrying never overwrites or recovers
another request's password. There is no registration-receipt table.
See the [managed example's wiring](https://github.com/yielded-dev/auth/blob/main/examples/persistence-drizzle-managed/src/live.ts).
`subjects.actionRequirements` can supply a distinct recovery or credential-change
policy; it defaults to `subjects.requirements`.

Reads use ordinary SQL without a commit journal or read-only transaction. Standalone
mutations use the shared commit owner and reject unrelated ambient transactions;
drivers without a reliable transaction marker fail closed. Combine protected
application writes through an explicit coordinator. Its receipt releases credentials
and events only after the outer owner commits; an unknown outcome does not authorize
another credential issuance or delivery.

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

`passwordMapping` maps your account, identifier, credential, and authority revision
tables. It is a `PasswordPersistenceMapping` from `@yielded/auth-persistence-drizzle`.
Supply `LifecycleHooks` and your other account/session Layers at the composition root.
Driver factories and transaction coordinators declare `Database` and Effect
`Crypto` requirements at acquisition. Provide your platform's Crypto Layer to
the persistence Layer itself and to Auth at your composition root. SHA digests and
entropy use Effect Crypto and may suspend.

Password lookup and rehash use the same native Effect SQL implementation for direct
SQL and interactive Drizzle drivers. Drizzle supplies table representations,
codecs, defaults, and update hooks; its captured SQL client owns execution.
Identifier lookup and candidate snapshot use separate statements so each mapped
ID column can retain its own physical encoding.

A replacement `PasswordPersistence` supplies `findCredential`, returning an optional
coherent credential snapshot without writes or a transaction held across hashing.
`rehashIfCurrent` conditionally updates only the verifier and its version when hash
parameters change; a lost comparison is a no-op. Rate limits belong to
`PasswordAttemptLimiter`, so no password attempt table or cleanup operation is needed.

Explicit session mappings declare every independently mutable subject input to
`decodeRequirement` in `subject.requirementColumns`. D1 requires this declaration;
use `[]` only for a constant decoder. Native coordinated owners re-evaluate the
decoder after application writes, while D1 guards the declared inputs in its batch.

`AuthenticationAuthority.capture` returns `{ revision, requirement }` from the same
subject read, including the full active factor vector. Requested credential IDs are
required anchors; `capture(subjectId, [])` still returns all active factors. Only
actual method verification produces proofs. Method credential snapshots also carry
that current requirement;
explicit email and passkey mappings derive it with `subject.decodeRequirement` from
the joined subject row rather than storing policy on the credential. Password sign-in reuses that requirement to choose a session or a
pending second factor. The committing session or password-mutation authority must
still check current status, policy, and the original revisions. Credential replacement
updates both the password and authority credential revisions; identifier removal,
rebinding, or eligibility changes must atomically bump the subject security revision.

Session issuance has no flow-deduplication table. Each method consumes its own proof
before issuance; an unknown issuance outcome requires a new authentication ceremony.
D1 checks the original authority through its fixed guarded batch.

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

Stateful session verification reads the session and subject in one SQL snapshot
when their mapped IDs have compatible SQL types and encodings. Application claims
may require their own query; join the required account fields in that query.
Explicit session reads always check current storage.

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

Adapter authors can supply mapped table contracts or implement `NativeSqlTables`;
both feed the shared strategy implementation and commit owner. Reuse the canonical
row codecs when composing explicit services:

```ts
import { makeStorageMappings } from "@yielded/auth-persistence/Adapter";
import { Effect } from "effect";

const proofMapping = Effect.gen(function* () {
  const mappings = yield* makeStorageMappings(storage);
  return mappings.proofs();
});
```

Mapping construction requires Effect `Crypto`; provide it at the calling Layer.
The layout must include each requested mapping's role tables. Drivers supply typed
table handles, column codecs, SQL expressions, and the transaction or fixed-batch
boundary. D1 builds its named assertions from the shared statements. Refine authority
policy only for the intended proof purpose; the composed Layer's defaults remain unchanged.

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

## SQL session verification

Interactive SQL adapters read a stateful session and its subject in one statement
when both owner columns use compatible physical text types and collations without
codecs. Service construction checks that compatibility with one catalog read.
Custom codecs, incompatible columns, and converters without this metadata use two
reads: discover the owner, then read both rows together and validate their ownership.
Rebuild persistence Layers after schema migrations.

SQL state-assisted validity reads the subject's current security revision and its
owner-scoped revocation tombstone in one statement. Each ID uses its own column
codec. Both modes check current authority and fresh expiry times on every read;
committed revocations retain immediate invalidation.

Ordinary verification uses plain reads. A caller-owned transaction retains the
database's normal query-failure behavior. Mutation transaction and receipt
guarantees still apply.

Explicit session mappings require `moduleId`, the shared engine clock, and the
native active-status values. Session rotation uses the captured record and old
digest as its guard; there is no row-version column or session-flow table.
`SessionPendingTables` maps one module-scoped table for `Login` and `StepUp`, with
an exact digest key and kind on every read or write. The Login codec preserves
application claims. `SessionCleanup` shares one total deletion limit across
expired pending proofs and due revocation tombstones; see [session maintenance](./sessions#custom-composition).

## Passwords

Use `makePasswordPersistenceServices` for verification and mutation storage;
`makePasswordRegistrationServices` supplies registration authority. Reset support
also needs a proof mapping.

Password verification consumes token-bucket budgets through `PasswordAttemptLimiter`
before credential verification. Its default store is process-local, resets on
restart, and has a fixed 10,000-key capacity. Multiple instances and per-request
runtimes need a [shared store](../guide/passwords#share-rate-limits) for identifier
and subject buckets; the action bucket stays per instance. Consumed tokens are never refunded.

```text
password mutation transaction
  ├─ check account + credential revisions
  ├─ update password and security revision
  └─ commit receipt
```

Use the adapter's coordinator when combining authentication with application writes.
Coordinated password mutations, including a reset's proof redemption, are checked again
after your writes; changing their account, credential, or proof rows in the same commit
rolls both back.
Do not put standalone services inside an untracked raw Drizzle transaction.

## Proof storage

Map one proof row keyed by module, purpose, and canonical identifier/subject series.
Issue uses the database clock and preserves a live code unless the complete binding
matches. Redemption conditionally deletes the exact unexpired code or increments
that code's bounded failure count. No request receipt, continuation, delivery claim,
or SQL rate-limit tables remain.

Subject-bound standalone redemption takes one subject lock without rereading
factor or identifier authority. Protected password, email, and phone mutations
redeem inside their native owner after its existing subject lock;
standalone sign-in consumes first and issues a session independently. Cleanup uses
`CleanupLimit` and returns `{ removed, hasMore }`; `hasMore` means the limit was
reached. Retired phone identifiers are permanent and never part of cleanup.

Reset development proof tables, removed command/registration-receipt tables, and
the replaced phone identifier layout when adopting these pre-production schemas.

## Email

`makeEmailSignInServices` performs lookup. `makeEmailRegistrationServices` and
`makeEmailAddressServices` own account creation and address changes.

For explicit composition over an existing storage layout, start from
`yield* makeStorageMappings(storage)` and use its `.emails()` and `.proofs()` factories.
Supply the raw registration mapping's synchronous provisioning and inspection policy.

Email registration provisions a fresh subject after mailbox proof. Its application
inspection and committing identifier policy may admit absent or active-unverified
targets for reclamation. Scope that permission to email registration. The owner
rechecks the old account, binding revision and unverified state before updating
ownership atomically with proof redemption; D1 compiles the same commit guards.

Reclamation advances the previous subject's security revision without moving its
credentials or application data. Identifier eligibility is separate from the prior
subject's status: a disabled subject stays disabled. Sessions and pending authentication must consult
that revision for immediate invalidation; purely stateless sessions retain their
documented lifetime. Provisioning, reclamation and proof consumption share one
transaction or D1 batch. Verified addresses cannot be reclaimed. Provisioning
completes synchronously; the authority supplies a stable `requestId` for application
idempotence. An application can own a
queue when its account system requires asynchronous work. Compose this guest workflow explicitly as shown in
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

Import `OAuthPersistence` from `@yielded/auth-persistence` for upstream provider
accounts through Effect SQL. It uses the same operation implementations as the
Drizzle companion. These explicit factories are separate from the composed
`AuthPersistence.make` Layer and from downstream `OAuthServerPersistence` storage.

| Factory                                | Workflow                                                        |
| -------------------------------------- | --------------------------------------------------------------- |
| `makeOAuthSignInServices`              | Single-use sign-in flows and existing login credentials         |
| `makeOAuthRegistrationIntentServices`  | Verified identity to registration intent                        |
| `makeOAuthRegistrationServices`        | Application provisioning, login credential, and durable receipt |
| `makeOAuthAccountsServices`            | Linking and safe unlinking with exact-action evidence           |
| `makeOAuthConnectedServices`           | Retained grants, listing, use, refresh, and disconnect          |
| `makeOAuthConnectedRevocationServices` | Durable provider-revocation work                                |

Direct Effect SQL supports PostgreSQL and SQLite clients with interactive
transactions. It does not supply a MySQL, D1 batch, or native Kysely adapter.
Use the existing Drizzle entrypoints for their documented driver-specific behavior.
The [Effect SQL consumer](https://github.com/yielded-dev/auth/tree/main/examples/persistence-sql)
has no Drizzle dependency.

Describe physical tables with `OAuthPersistence.table`, then map semantic columns,
row codecs, subject IDs, authority predicates, and required unique keys. Tables
remain application-owned; construction checks the required keys against the actual
database. `OAuthPersistence.clock` supplies an integer-millisecond engine clock.
Use `sql`, `eq`, and `and` from that namespace for mapping expressions. These are
mapping expressions; application queries use the supplied Effect `SqlClient`.

```ts
import { OAuthPersistence } from "@yielded/auth-persistence";
import { Persistence } from "@yielded/auth";
import { Layer } from "effect";

import { SqlLive, CryptoLive, signInMapping } from "./infrastructure";

export const OAuthStorageLive = OAuthPersistence.oauthSignInPersistenceLayer(
  OAuthPersistence.makeOAuthSignInServices(signInMapping),
).pipe(Layer.provide([SqlLive, CryptoLive, Persistence.hooksLayer]));
```

If session storage does not already supply `AuthenticationAuthority`, use
`makeAuthenticationAuthorityServices` with the same subject and shared credential
mapping. Session issuance must check that authority alongside the OAuth credential.

Factories capture the client at construction. Standalone methods own their commit
and reject ambient transactions. For atomic application work, use the matching
`coordinateOAuth*({ mapping }, body)` function; registration additionally takes its
`target` service. The body receives transaction-bound persistence, and queries
through the same `SqlClient` participate in that transaction. Keep provider network
exchanges outside it. Bound services cannot escape the coordinator. Registration compares its retained application binding before allocating IDs or
provisioning. The registration Schema owns the canonical stored payload.

### Kysely-owned schemas

Keep Kysely as your migration and application-query tool, and map those physical
tables for Effect SQL. Both clients may address the same database, but a Kysely
transaction does not become an Effect SQL transaction. Provisioning and auth writes
that must commit together must run through the adapter's coordinator and its exact
Effect SQL client. Otherwise supply a replacement persistence service that owns
both operations under your application's transaction authority. No native Kysely
integration is implied by table mapping.

An external provider exchange cannot be rolled back with your database. A single conditional callback consume precedes provider exchange. Unknown exchange
or commit outcomes require a fresh ceremony. Refresh alone retains a durable
external-work claim and never permits expired takeover. Linking preserves tuple
uniqueness; unlinking rechecks remaining login methods and retained-grant references
before releasing ownership. Login-credential listing is an application query over
its mapped tables; connected-grant listing belongs to `OAuthConnectedPersistence`.

## Passkeys

`makePasskeyPersistenceServices` inserts challenges, reads their context, consumes
verified challenges, and deletes expired rows in bounded batches.
`PasskeyCredentials` supplies credential lookup and `listForSubject`, which returns
the subject's current factor revisions, same-RP exclusions, and an optional existing
user handle. Each credential retains its own handle.

After signature verification, one transaction conditionally deletes the unexpired
challenge and updates the credential counter. A failed or uncertain consume never
issues a session. Session issuance separately rechecks subject and credential
authority; if it fails, begin a new ceremony.

Enrollment stores the application's begin authorization with the challenge. Its
completion locks the subject, re-assesses that authorization and the current
credential cap, and atomically inserts the credential and shared factor. Enrollment
preserves the subject security revision and existing sessions. Removal protects the
last usable sign-in method, bumps the revision, and applies session invalidation
under the same subject lock. Registration stores its original schema-encoded
application payload on the challenge row and provisions synchronously on completion.

Use `coordinatePasskeyManagement` or `coordinatePasskeyRegistration` when application
writes share the transaction. A failed auth operation poisons that transaction:
the outer commit fails even when the application catches the error, so retry in a
fresh transaction.

Standalone reads open no transaction. Credential lookup uses one SELECT when mapped
references share compatible SQL types and ID encodings; custom codecs that transform
IDs outside SQL require additional mapped reads. Passkey budgets use Effect's
`RateLimiter`, with a bounded process-local default. Supply a
[shared store](../guide/passwords#share-rate-limits) for subject and target limits
across replicas; the global budget stays per instance.

## TOTP

`TotpMapping.subject.requirementColumns` follows the same policy-input contract as
session mappings: declare all mutable decoder inputs, or `[]` for constant policy.
D1 rejects omission. Both native and batch owners retain the original authority
vector and authorization deadline.

Recovery reset maps the same Login pending table and codec as sessions. The owner
matches its module, kind, original digest, binding and credential revisions; a
step-up intent cannot authorize recovery reset. Recovery-code regeneration changes
the factor version while preserving the subject revision and existing sessions.

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
`PhonePersistence` and `PhoneSignInTargets`, with empty hook
defaults. Both persistence Layers use the application's explicit `CryptoLive`.
The proof Layer stores one current code per series, its failed-attempt count, and
cooldown. Core `ProofLimiter` and `PhoneAdmission` own token-bucket limits; configure
their Layers separately from table mappings. Sign-in uses lookup and admission; number-management operations
also use `PhonePersistence`. You provide table mappings and
migrations. See the [SQLite example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts)
for the table definitions and mappings.

<!-- #endregion phone-layers -->

## Connected OAuth grants

`OAuthPersistence.makeOAuthConnectedServices` and
`OAuthPersistence.makeOAuthConnectedRevocationServices` coordinate
provider grants, refresh attempts, and optional revocation. Map `otherReferences`
to an indexed SQL predicate for concrete login, grant, or job references sharing
identity ownership. Unlink/disconnect release ownership only when those references
are absent. Keep the durable grant identity and refresh version/claim predicates;
no ordinary callback claim or token-use admission row is needed.

Core assesses action evidence once. The committing adapter checks the accepted
authorization's exact subject, action, flow, target, revisions, and fixed deadline;
it does not reassess factor evidence. Map independent application policy through
the current `policy.condition` predicate.

For `OAuth.make({ access: profile })`, use the same connected services alongside
`makeOAuthSignInServices` and map `credential` to the shared login table. Live flow
rows contain their Schema snapshot and exact callback predicates. The
[OAuth storage example](https://github.com/yielded-dev/auth/blob/main/examples/shared/oauth/storage.ts)
shows the application-owned schema and authority. Cleanup accepts a shared
`CleanupLimit` and returns `{ removed, hasMore }`; `hasMore` means the batch limit
was reached, so another call can remove zero rows.

<details>
<summary>D1 and Durable Object transaction boundaries</summary>

D1 uses a preplanned conditional batch, not an interactive transaction. Allocate
registration IDs before the batch. Named final checks run after all staged application
statements; native coordinated owners likewise check after the application callback.
Declare every independently mutable requirement-decoder input in
`subject.requirementColumns`; use `[]` only for constant policy. Do not replay a
caller-owned mutation after an ambiguous response.

Durable Object SQLite uses the captured Effect SQL client's asynchronous
`storage.transaction` boundary. Use `SqliteDo.databaseLayer` or
`SqliteDo.makeDatabase(existingDrizzle)` and the adapter's transaction coordinators;
crypto Effects may suspend inside that owned transaction. An arbitrary raw Drizzle
outer transaction, including its `transactionSync` callbacks, is unsupported.
No synchronous crypto implementation or `Effect.runSync` bridge is required.

Compatible scalar mappings, including application-owned tables and renamed columns,
use grouped cleanup reads and writes, with atomic checks after application work and
database triggers. Groups split at the driver's statement and bound-data limits.
An arbitrary SQL-producing encoder or binary/array representation may require its
original mapped statements because it cannot be encoded as a scalar rowset.
Collation aliases and staged D1 writes can also require additional statements;
a page size alone does not determine its cost.
Budget every statement and transaction-control call as a database roundtrip.
Direct Effect SQL uses SQLite limits that also fit Durable Objects.

</details>

See [integration references](../guide/examples#database-adapters) for concrete
table definitions and mappings.
