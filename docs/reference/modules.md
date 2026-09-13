---
description: Public imports, browser-safe contracts, and optional adapters.
---

# Public modules

Start with `Auth.make` to compose authentication for an application. Choose
individual modules for your methods, session strategy, and integration boundaries.

## Imports and tree shaking

Core modules support both root namespaces and direct subpaths:

```ts
import { Identity, SessionContract } from "@yielded/auth";
// The same modules, selected directly:
import * as IdentityModule from "@yielded/auth/Identity";
import * as SessionContractModule from "@yielded/auth/SessionContract";
```

Use root imports for application composition. Use direct paths for smaller
esbuild bundles and lazy loading; esbuild can retain unused members of a
re-exported namespace. Both styles keep operations on their module, such as
`Http.layer`, `PasskeyContract.make`, and `TotpContract.make`.

Native ESM loads the root's static dependencies. Direct paths also keep that
module-loading boundary narrow when running without a bundler.

Optional adapters are direct imports, for example `@yielded/auth/DrizzlePostgres`,
`@yielded/auth/OpenIdClient`, or `@yielded/auth/PasskeyBrowser`. Install only the peers
required by the selected adapters. `@yielded/auth/Testing` remains test-only.

## Application composition

Import these as `@yielded/auth/<Module>` or as namespaces from `@yielded/auth`:

| Modules                       | Purpose                                                                |
| ----------------------------- | ---------------------------------------------------------------------- |
| `Auth`                        | Application service, strategies, and request boundaries.               |
| `Identity`, `Schema`          | Subject identifiers, claims, and shared schemas.                       |
| `Operations`, `Hooks`         | Operation contracts and lifecycle hooks.                               |
| `Sessions`                    | Session strategies, persistence ports, and lifecycle operations.       |
| `Password`                    | Password registration, sign-in, and account changes.                   |
| `Email`, `PhoneOtp`, `Proofs` | Email and phone methods, bound proofs, and private delivery.           |
| `Totp`, `Passkey`             | Additional factors and passkey workflows.                              |
| `OAuth`                       | Provider sign-in, registration, linked accounts, and connected grants. |

## Browser and transport boundaries

Keep shared browser/server definitions in the contract modules. Import browser
helpers separately from server verifiers and persistence adapters.

| Modules                                              | Purpose                                                             |
| ---------------------------------------------------- | ------------------------------------------------------------------- |
| `AuthContract`                                       | Shared named actions, schemas, and native HttpApi groups.           |
| `Http`                                               | Request context, cookies, middleware, and mounting named auth APIs. |
| `Client`                                             | Scoped service with typed `client.auth` methods.                    |
| `SessionContract`, `PasskeyContract`, `TotpContract` | Shared public schemas without server orchestration.                 |
| `OperationHttp`                                      | Shared operation HTTP descriptors.                                  |
| `OperationHttpClient`, `OperationHttpServer`         | Client execution and server routing.                                |
| `Atom`                                               | Effect Atom queries, mutations, and client workflows.               |
| `HttpServer`, `Rpc`                                  | Lower-level HTTP and RPC integrations.                              |

`AuthContract`, `Http`, `Client`, `Atom`, and the contract modules are also root
namespaces. Shared and browser examples use direct paths to keep bundles narrow.
React applications use `@effect/atom-react` with the same importable atoms;
Yielded Auth has no React-specific export.

See [HTTP and client state](../guide/http-and-client) for contract sharing and
client workflow composition.

## Optional adapters

These are available through direct subpaths only:

| Modules                                                                         | Integration                                             |
| ------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `OpenIdClient`, `OpenIdClientConnected`                                         | OAuth/OIDC verification and connected grant management. |
| `GitHub`                                                                        | GitHub provider configuration and operations.           |
| `PasskeySimpleWebAuthn`, `PasskeyBrowser`                                       | Server verification and browser WebAuthn ceremonies.    |
| `PasskeyPassword`                                                               | Password-backed authority for passkey workflows.        |
| `Drizzle`                                                                       | Shared Drizzle adapter contracts.                       |
| `DrizzlePostgres`, `DrizzlePglite`, `DrizzleMysql2`                             | PostgreSQL, PGlite, and MySQL drivers.                  |
| `DrizzleLibsql`, `DrizzleD1`                                                    | libSQL and Cloudflare D1 drivers.                       |
| `DrizzleSqliteBun`, `DrizzleSqliteNode`, `DrizzleSqliteWasm`, `DrizzleSqliteDo` | SQLite drivers by runtime.                              |
| `Cloudflare`                                                                    | Cloudflare platform integration.                        |

The [adapter guide](./adapters) covers transaction authority, durable receipts,
and runtime constraints.

## Focused service modules

These direct subpaths expose individual services and contracts for lower-level
composition. Start with `Auth.make` for application authentication.

| Modules                                                     | Responsibility                                      |
| ----------------------------------------------------------- | --------------------------------------------------- |
| `AuthSession`, `AuthStore`, `AuthTokenCodec`                | Session values, storage, and token codecs.          |
| `PasswordAuth`, `PasswordCredentialStore`, `PasswordHasher` | Password services, storage, and hashing.            |
| `EmailOtp`, `EmailOtpSender`                                | Email OTP service and delivery.                     |
| `IdentityResolver`, `Policy`                                | Identity resolution and authentication policy.      |
| `Errors`, `Workflows`, `WebCrypto`                          | Errors, workflow composition, and cryptography.     |
| `Testing`                                                   | Test-only helpers; exclude from production imports. |

API comments and signatures live beside the
[public source modules](https://github.com/yielded-dev/auth/tree/main/packages/effect-auth/src).
