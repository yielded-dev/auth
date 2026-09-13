---
description: Mount a shared auth API, configure cookies, and compose Effect Atom workflows.
---

# HTTP and client state

One shared contract supplies local server methods, HTTP endpoints, and a named
client. Effect Atom owns client queries, mutations, and workflows.

```text
AuthApi ──→ Auth.make ──→ local Effects + HTTP handlers
    └─────→ Client.make ──→ client.auth + Effect Atom ──→ UI
```

## Define the routes

Keep the contract safe to import in both the browser and server:

```ts [auth-contract.ts]
import { Schema } from "effect";
import * as AuthContract from "@yielded/auth/AuthContract";

export const AuthApi = AuthContract.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  actions: (sessions) => ({ signIn: AuthContract.passwordSignIn(sessions) }),
});
```

The contract includes `getSession`, `requireSession`, `signOut`, and `renewSession`.
It exposes only the additional actions you select. Installing a strategy does
not publish all its methods.

| Actions                             | HTTP method | Default path                                          |
| ----------------------------------- | ----------- | ----------------------------------------------------- |
| `getSession`, `requireSession`      | GET         | `/auth/getSession`, `/auth/requireSession`            |
| `signIn`, `signOut`, `renewSession` | POST        | `/auth/signIn`, `/auth/signOut`, `/auth/renewSession` |

No-input queries use GET. Queries with payloads use POST so their inputs stay out
of URLs. Change the shared prefix with `basePath` on `AuthContract.make`; server
and client use the same descriptors.

## Configure the server

Bind the contract to your methods and session configuration:

```ts [auth.ts]
import { Auth, Http, Password, Sessions } from "@yielded/auth";

import { AuthApi } from "./auth-contract";

export const AppAuth = Auth.make(AuthApi, {
  sessions: Sessions.stateful(),
  strategies: { password: Password.make() },
  defaultStrategy: "password",
});

export const AuthRoutes = Http.layer(AppAuth, { origin: "https://app.example.com" });
```

`Http.layer` mounts the shared actions and configured OAuth callbacks, and
supplies `AppAuth.layer`. Provide your stores and account authority to the result.
The [adapter guide](../reference/adapters#compose-the-application-layer) shows the
`AuthDependencies` composition used below.

For an existing raw `HttpRouter`, merge the auth route Layer with your application
routes:

```ts [routes.ts]
import { Layer } from "effect";

import { ApplicationRoutes } from "./application-routes";
import { AuthRoutes } from "./auth";
import { AuthDependencies } from "./auth-live";

export const Routes = Layer.mergeAll(AuthRoutes, ApplicationRoutes).pipe(
  Layer.provide(AuthDependencies),
);
```

### Application routes

For application routes that call auth, build the middleware with `Http.make`:

```ts [auth-http.ts]
import { Http } from "@yielded/auth";

import { AppAuth } from "./auth";

export const http = Http.make(AppAuth, { origin: "https://app.example.com" });
```

Wrap those route Layers with `ApplicationRoutes.pipe(http.middleware,
Layer.provide(AppAuth.layer))` before merging them above.

The middleware creates fresh request context and delivers credential cookies on
the response. It accepts ordinary JSON, form, and multipart routes. Inside those
routes, call `auth.getSession()`, `auth.requireSession()`, or `auth.signOut()` after
`const auth = yield* AppAuth`. These are local Effects; they do not make HTTP calls
or require a headers argument.

### Join an existing HttpApi

Add the native auth group beside your application groups in the shared API:

```ts [api.ts]
import * as AuthContract from "@yielded/auth/AuthContract";
import { HttpApi } from "effect/unstable/httpapi";

import { AuthApi } from "./auth-contract";
import { Projects } from "./projects-contract";

export const Api = HttpApi.make("app").add(Projects, AuthContract.httpGroup(AuthApi));
```

```ts [api-server.ts]
import { Layer } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { Api } from "./api";
import { http } from "./auth-http";
import { AuthLive } from "./auth-live";
import { ProjectHandlers } from "./projects-handlers";

export const Routes = HttpApiBuilder.layer(Api, { openapiPath: "/openapi.json" }).pipe(
  Layer.provide(http.handlers(Api)),
  Layer.provide(ProjectHandlers),
  http.middleware,
  Layer.provide(AuthLive),
);
```

Both mounting forms use the same bounded transport and handlers. The group defaults
to `auth`; pass matching `{ name: "account" }` options to `httpGroup` and `handlers`
to rename it. Middleware and annotations compose normally, with their requirements
visible in Layer types. Configure paths in the contract's `basePath` rather than
prefixing generated endpoints afterward.

The [shared contract](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-contract.ts)
and [server example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-server.ts)
show a complete group and handler pair.

### Cookies and protected handlers

Cookies default to `Secure`, `HttpOnly`, `SameSite=Lax`, path `/`, and the
`__Host-effect-auth-` prefix. Override `cookie.name` for the session slot or
`cookie.prefix` for all slots. Plain HTTP development requires an explicit
`cookie.secure: false`. Use your real HTTPS origin; never derive trusted origins
from an untrusted request header.

POST auth actions require the configured Origin, JSON content type, and
`x-effect-auth-csrf: 1` by default. GET actions have no body or CSRF header and
reject an explicitly untrusted Origin. Duplicate credential cookies are rejected,
and session responses are not cacheable. If you override `csrf` on the server,
pass matching settings to `Client.make`.

`http.middleware` supplies context; it does not require every route to be signed
in. Call `auth.requireSession()` in protected application handlers. For declarative
HttpApi protection, define `makeSessionHttpContract` from `@yielded/auth/SessionContract`,
attach its `RequireSession` middleware, and read `CurrentSession` in handlers.
Provide `http.securityLayer(contract)` and apply `http.middleware` to the route
Layer. Its cookie name must match the adapter. It declares 401 for absent or
invalid sessions and 503 for unavailable verification. See the
[session HTTP example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/session-http.ts).

Named mutations enforce Origin and CSRF before side effects, including local
calls from application routes. Raw strategy methods are treated as mutations.
For a custom credential-producing workflow, call `http.protect(effect)` inside
the request boundary; it applies mutation policy and supplies private collectors
without imposing a body format. Custom hosts still own webhook validation and
ordinary application mutation policy.

## Expose another method

The method guides show the available local strategy calls. Browser access requires
an action in `AuthApi`: `AuthContract.passwordSignIn` is the password shortcut;
`AuthContract.fromOperation` reuses a pure operation contract; `AuthContract.action`
accepts explicit payload, success, and error schemas.

Each action selects a server `method` and, when needed, a `strategy`. The method
defaults to the action's name. You can expose two strategies under different names
without making the client choose a strategy string. Configure only actions your
application intends to serve. Passkey and TOTP have dedicated pure contract modules;
the email, phone, and OAuth flows currently require explicit action schemas.

Map private method inputs through `requestFields` when declaring an action:

| Method input                                                         | Credential slot      |
| -------------------------------------------------------------------- | -------------------- |
| Email, phone, or OAuth `requestBinding`; passkey `bindingCredential` | `request-binding`    |
| Email continuation `credential`                                      | `proof-continuation` |
| TOTP `pendingCredential`                                             | `pending-proof`      |

The server injects those values from `Auth.AuthRequest`; both named local calls and
remote payloads omit them. Set `credentials: true` for actions that issue or clear
credentials, declare any private reveals, and supply a `subject.fromSuccess`
projection for actions that establish or replace the authenticated account.
`fromOperation` carries forward the operation's schemas, replay policy, credential
delivery, and reveal declarations; the subject projection remains explicit.

See the [passkey contract](./passkeys#define-the-shared-actions) for a complete
example and [TOTP](./totp#expose-private-reveals-over-http) for private reveals.

## Call the client directly

```ts [client-service.ts]
import * as Client from "@yielded/auth/Client";

import { AuthApi } from "./auth-contract";

export const AppClient = Client.make(AuthApi, { baseUrl: "https://app.example.com" });
```

Inside an existing Effect with `AppClient` provided:

<!-- prettier-ignore -->
```ts
const client = yield* AppClient;
const session = yield* client.auth.getSession();
```

`Client.make` declares a yieldable service. Provide `AppClient.layer` to a program,
or yield `AppClient.make` inside a Scope to acquire an instance directly.
`client.auth.signIn({ email, password })` and `client.auth.signOut()` return Effects
with typed errors and schema requirements. The client handles envelopes and CSRF;
the browser manages Origin and cookies. Mutations are never automatically retried.

The native HttpApi group documents the exact transport envelopes. A plain
`HttpApiClient` does not supply the auth client's credential settlement, private
reveal handling, or account transition coordination.

## Connect client state

```ts [auth-client.ts]
import * as AuthAtom from "@yielded/auth/Atom";

import { AppClient } from "./client-service";

export const auth = AuthAtom.make(AppClient);
```

Both constructors are synchronous and perform no I/O. The application Atom
registry owns client acquisition and finalization. `auth.getSession` is a query
atom, `auth.session` is its alias, and `auth.signIn` and `auth.signOut` are mutation
atoms. Queries expose loading, success, and failure through `AsyncResult`,
including setup errors.

Compose application queries with the same scoped client:

```ts [member-name.ts]
import { Effect } from "effect";

import { auth } from "./auth-client";
import { AppClient } from "./client-service";

export const memberName = auth.runtime.atom(
  Effect.gen(function* () {
    const client = yield* AppClient;
    const session = yield* client.auth.getSession();

    return session?.claims.displayName ?? null;
  }),
);
```

Pass a `services` Layer to `AuthAtom.make` when response codecs require services;
the types require this option when necessary. Its optional `layer` replaces the
configured client Layer for testing or a custom implementation. A separately
provided `AppClient.layer` acquires a separate instance unless the host deliberately
shares its Layer memo map.

### React

Use the standard `@effect/atom-react` adapter and the application's ordinary
`RegistryProvider`. Yielded Auth has no React-specific provider or hooks:

```tsx [account.tsx]
import { useAtomSet, useAtomValue } from "@effect/atom-react";

import { auth } from "./auth-client";

export function Account() {
  const session = useAtomValue(auth.session);
  const signOut = useAtomSet(auth.signOut);

  if (session._tag === "Initial") return <p>Loading…</p>;
  if (session._tag === "Failure") return <p>Session unavailable</p>;
  if (session.value === null) return <p>Signed out</p>;

  return (
    <button onClick={() => signOut(undefined)}>Sign out {session.value.claims.displayName}</button>
  );
}
```

Keep multi-step logic in Effects and workflow atoms. Components render and dispatch;
promise-mode handlers return the dispatch promise without `.then` chains. See the
[React example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-react.ts).

### Invalidation and account lifetime

Auth mutations refresh auth queries automatically. Extra reactivity keys describe
application data that must also refresh. Use the same runtime factory as the
queries subscribed to those keys:

```ts [shared-runtime.ts]
import * as AuthAtom from "@yielded/auth/Atom";
import { Atom } from "effect/unstable/reactivity";

import { AppClient } from "./client-service";

export const appRuntime = Atom.context();
export const auth = AuthAtom.make(AppClient, {
  runtime: appRuntime,
  reactivityKeys: { signIn: ["projects"], signOut: ["projects"] },
});
```

The default factory is `Atom.runtime`, with a separate memo map per registry.
`auth.runtime` owns account-scoped queries, workflows, and state read or written
inside them. An account transition disposes the old account registry before
publishing its replacement. Ordinary application atoms outside that runtime keep
their own lifetime; invalidation does not make them account-scoped.

Named auth mutations survive their own admitted sign-in or sign-out until the
public result settles. Unrelated account changes interrupt pending mutations and
clear previous results. Execute mutations by writing an input; refreshing their
result view does not resend credentials. Custom account-scoped workflows retire
on account replacement, including when they complete authentication. Awaiting
callers receive interruption. Use an application-owned lifetime for workflows
intentionally spanning accounts.

### Server rendering and hydration

Default atoms render `Initial` on the server without fetching. For session-aware
rendering, create request-local atoms with the encoded local `auth.getSession()`
result as `initialSession`. Acquire their runtime in a request-owned registry
before rendering to decode the seed, then provide that registry through the
standard Atom adapter. Serialize only the public session. Hydrate using a separate
browser registry and the same display seed; close each registry with its host Scope.

The seed is display data, not authentication authority. Runtime acquisition does
not fetch. Browser query reads verify the live cookie, and a result, failure, or
account change permanently retires the seed. Never share server registries,
clients, or request-bearing memo maps across requests, or apply generic late
hydration updates to auth atoms. The
[SSR example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/auth-ssr.ts)
shows rendering, hydration, and unmount finalizers.

## Compose a passkey workflow

The [passkey guide](./passkeys) defines both the server strategy and this shared
contract:

<!--@include: ./passkeys.md#passkey-contract-->

Bind `PasskeyApi` with `Auth.make(PasskeyApi, { sessions, strategies })` on the server,
using the same passkey configuration. `requestFields` removes private inputs from
the public schema and injects them from request credentials during execution.
Neither local nor HTTP callers can supply those private fields. For new contracts,
`AuthContract.action` also accepts explicit input, success, and error schemas.

```ts [passkey-workflow.ts]
import { Effect, Redacted } from "effect";
import * as AuthAtom from "@yielded/auth/Atom";
import * as Client from "@yielded/auth/Client";
import { makeSimpleWebAuthnPasskeyBrowser } from "@yielded/auth/PasskeyBrowser";

import { PasskeyApi } from "./passkey-contract";

export const PasskeyClient = Client.make(PasskeyApi, { baseUrl: "https://app.example.com" });
export const passkeys = AuthAtom.make(PasskeyClient);

export const signIn = passkeys.runtime.fn<{ flowId: string; commandId: string }>()(
  Effect.fn("app.passkeySignIn")(function* (input) {
    const client = yield* PasskeyClient;
    const browser = yield* makeSimpleWebAuthnPasskeyBrowser();
    const started = yield* client.auth.signIn({
      ...input,
      profileId: "default",
    });
    const response = yield* browser.authenticate({ started, mediation: "required" });

    return yield* client.auth.completeSignIn({
      flowId: input.flowId,
      response: Redacted.value(response.response),
    });
  }),
);
```

The atom owns the ceremony and cancellation. An admitted credential response
settles before publishing an account change; that change then retires this custom
workflow. Render the updated session rather than chaining UI work after its
completion. Unknown write outcomes require authoritative lookup or a fresh flow.

## Lower-level transports

`http.withRequest` wraps a custom Effect returning `HttpServerResponse`.
`http.operationLayer` supplies browser policy and caller resolution to existing
`OperationHttpServer` contracts. Those descriptors continue to own private payload
injection and explicitly selected reveals.
Encode expected response failures before leaving the request wrapper.

`OperationHttpClient`, `AuthAtom.query`, `AuthAtom.mutation`, and `AuthAtom.workflow`
remain available for custom integration. Private reveals belong in a finite
collector, outside ordinary query caches, logs, and persisted client state.
