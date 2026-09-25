---
title: Examples
description: Application compositions for authentication, persistence, and HTTP clients.
---

Use these source references to connect Yielded Auth to your application's accounts,
database, and request handlers. Each composition uses the package's public API.

## Authentication methods

| Source                                                                                                  | Integration                                   |
| ------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| [Passwords](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/password-methods.ts)        | Registration, sign-in, and account changes.   |
| [Email](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/email-methods.ts)               | Codes, magic links, and address workflows.    |
| [Phone OTP](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts)        | Phone authentication backed by SQLite on Bun. |
| [Password hashing](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/password-hashing.ts) | Hashing policy and verification.              |

Start with the [GitHub](./github) or [Google](./google) setup guide. The
[GitHub OAuth composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/github-oauth-app.ts)
shows provider and application wiring.

## Sessions and identity

| Source                                                                                           | Integration                                                    |
| ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| [Sessions](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/sessions.ts)          | Session lifecycle and strategy selection.                      |
| [Identity](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/identity-boundary.ts) | Application-owned subject identifiers and identity resolution. |
| [Proofs](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/proofs.ts)              | Bound proofs and private delivery.                             |
| [Hooks](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/lifecycle-hooks.ts)      | Lifecycle hook composition.                                    |

## Database adapters

| Source                                                                                                 | Integration                |
| ------------------------------------------------------------------------------------------------------ | -------------------------- |
| [SQLite on Bun](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/drizzle-sqlite-bun.ts) | Drizzle and SQLite on Bun. |
| [SQLite WASM](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/drizzle-sqlite-wasm.ts)  | Drizzle and SQLite WASM.   |

The [Node SQLite](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/drizzle-sqlite-node.ts)
and [libSQL](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/drizzle-libsql.ts)
files provide additional composition references. See [adapters and persistence](../reference/adapters)
for transaction and retry requirements.

## HTTP and browser clients

Start with the named API examples:

| Source                                                                                                 | Integration                                          |
| ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| [Shared contract](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-contract.ts)    | Auth actions beside an existing HttpApi group.       |
| [Server](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-server.ts)               | `Auth.make`, handlers, and raw router mounting.      |
| [Client](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-client.ts)               | `Client.make`, importable atoms, and Effect queries. |
| [React](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-react.ts)                 | Standard Atom registry and hooks.                    |
| [SSR](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-ssr.ts)                     | Request-local registries and session hydration.      |
| [Protected endpoints](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/session-http.ts) | Typed session middleware on an HttpApi.              |

The Studio example separates
[auth composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/studio-auth.ts),
[HTTP server](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/studio-http-server.ts),
and [browser client](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/studio-browser.ts).
These are lower-level integration references rather than a packaged application.
The [HTTP and client state guide](./http-and-client) explains contract sharing.

Example stores, keys, delivery services, and policies are disposable development
fixtures. Replace them with your application's authority and durable adapters before
using the same composition in a deployed service.
