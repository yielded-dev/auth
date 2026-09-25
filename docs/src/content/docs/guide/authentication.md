---
title: How it fits together
description: See how methods, sessions, and application services connect.
---

Your app owns users and storage. Yielded Auth verifies authentication methods and
issues sessions through those services.

```text
your request handler
  → AppAuth
      → password / passkey / email / OAuth
          → verify evidence
          → your account authority
          → session persistence
      → public result
  → private cookie delivery
```

## One contract, named methods

[`AuthContract.make`](./getting-started#define-the-shared-contract) declares the
shared actions. Bind them to server methods with `Auth.make(AuthApi, options)`
and to HTTP calls with `Client.make(AuthApi, options)`.

In an existing server Effect handler, with `AppAuth` provided:

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.signIn({ email, password });
```

In an existing client Effect, with `AppClient` provided:

<!-- prettier-ignore -->
```ts
const client = yield* AppClient;
const result = yield* client.auth.signIn({ email, password });
```

The inputs and public results come from the same contract. Local calls resolve
`Auth.AuthRequest` when they run; the HTTP middleware supplies it. Remote calls
use the named client's transport. Both preserve typed failures and validate the
declared schemas.

For reactive clients, `AuthAtom.make(AppClient)` supplies ready-to-use session
queries and named mutation atoms. Your application composes them through its Atom
registry and `auth.runtime`. A wrapper is useful when it adds application behavior,
such as a multi-step workflow or a response projection; direct auth calls already
return Effects.

## Configure once, resolve each request

`Auth.make` declares the service synchronously. Provide `AppAuth.layer` at the
application boundary, or yield `AppAuth.make` to acquire an instance in your Scope.
Keep request context out of the shared service Layer. `Auth.Service<Self>()` is
available when you prefer a class declaration.

`auth.getSession()` reads the incoming credential and returns a typed session or
`null`. `auth.requireSession()` requires authentication, while `auth.signOut()` and
`auth.renewSession()` deliver credential changes through the same boundary.
See [sessions](./sessions) for outcomes and failure behavior.

Installing a strategy makes its methods available locally; only declared actions
are exposed remotely. Each strategy adds its service requirements to the Layer's
type. [Getting started](./getting-started#add-another-method) shows local strategy
selection, and the [HTTP guide](./http-and-client#compose-a-passkey-workflow) shows
exposing another method through the shared contract.

## Sign-in flows by method

These are the local method names; shared contracts choose which calls to expose:

| Method                             | Flow                                                                          |
| ---------------------------------- | ----------------------------------------------------------------------------- |
| [Password](./passwords)            | `signIn` → session or additional factor.                                      |
| [Email code / magic link](./codes) | `beginSignIn` → `signIn` sends the proof → `verifySignIn` → `completeSignIn`. |
| [SMS code](./phone)                | `signIn` sends the code → `completeSignIn`.                                   |
| [Passkey](./passkeys)              | `signIn` → browser ceremony → `completeSignIn`.                               |
| [OAuth](./oauth)                   | `signIn` → provider redirect → `completeSignIn`.                              |
| [TOTP](./totp)                     | Primary method returns a pending proof → `verifyPending`.                     |

Multi-step methods retain public flow identifiers between calls. Private request
binders and continuation credentials travel through the request boundary. The
[HTTP guide](./http-and-client#expose-another-method) explains how shared actions
remove those fields from both server and client call inputs.

## What goes where

```text
src/
├─ auth-contract.ts    # shared claims and exposed actions
├─ auth.ts             # server methods and session selection
├─ auth-config.ts      # session policy, keys, allowed origins
├─ auth-persistence.ts # database mappings and transaction authority
├─ auth-accounts.ts    # account lookup, claims, provisioning
├─ auth-http.ts        # selected routes and cookie policy
└─ auth-client.ts      # queries, mutations, and UI workflows
```

Keep `Auth.AuthRequest` local to each request. Keep reusable services in Layers
whose resources belong to the application's Scope.

## Results and credentials

| Value                                                    | Where it goes                       |
| -------------------------------------------------------- | ----------------------------------- |
| Session claims, public status, challenge reference       | Operation result.                   |
| Session cookie, request binding, continuation credential | Private credential command sink.    |
| TOTP enrollment secret, recovery codes                   | Explicit, temporary private reveal. |

The [HTTP adapter](./http-and-client) implements these transport boundaries.
[Effect Atom](./http-and-client#connect-client-state) composes the browser workflow.

## Commit order matters

```text
prepare mutation → commit your transaction → read receipt → deliver credentials
```

`LifecycleHooks` run around these boundaries. A durable notification needs an
outbox in the same transaction. If the commit outcome is unknown, look it up
through the owning adapter; never assume repeating credential issuance is safe.

Continue with [sessions](./sessions) or [database adapters](../reference/adapters).
