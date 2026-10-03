---
title: HTTP and action contracts
description: Route defaults, cookies, request policy, and explicit action declarations.
---

Start with [HTTP integration](../guide/http-and-client) to compose the server,
and the [Effect Atom client](../guide/client) to call it. Both use the same
`AuthContract`; this page covers the transport details and custom actions.

## Route defaults

| Actions                             | HTTP method | Default path                                          |
| ----------------------------------- | ----------- | ----------------------------------------------------- |
| `getSession`, `requireSession`      | GET         | `/auth/getSession`, `/auth/requireSession`            |
| `signIn`, `signOut`, `renewSession` | POST        | `/auth/signIn`, `/auth/signOut`, `/auth/renewSession` |

No-input queries use GET. Queries with payloads use POST so their inputs stay out
of URLs. Change the shared prefix with `basePath` on `AuthContract.make`; server
and client use the same descriptors.

The HttpApi group defaults to `auth`. To rename it, use the same name in the
shared contract and server handlers:

```ts
// Shared API
AuthContract.httpGroup(AuthApi, { name: "account" });

// Server Layer
http.handlers(Api, { name: "account" });
```

Configure paths through `basePath` rather than prefixing the generated endpoints.

## Cookies and request policy

Cookies default to `Secure`, `HttpOnly`, `SameSite=Lax`, path `/`, and the
`__Host-effect-auth-` prefix. Override `cookie.name` for the session slot or
`cookie.prefix` for all slots. Secure custom names and prefixes must begin with
`__Host-`; their cookies retain path `/` and no Domain. `cookie.secure: false` is
allowed only with HTTP loopback origins (`localhost`, `127.0.0.1`, or `[::1]`).
Use your real HTTPS origin; never derive trusted origins from an untrusted request
header. Invalid combinations fail startup.

OAuth callbacks need the request-binding cookie on a cross-site return. Keep
`SameSite=Lax`; configuring OAuth with `cookie.sameSite: "strict"` fails startup.

POST auth actions require the configured Origin, JSON content type, and
`x-effect-auth-csrf: 1` by default. GET actions have no body or CSRF header and
reject an explicitly untrusted Origin. Duplicate credential cookies are rejected,
and session responses are not cacheable. If you override `csrf` on the server,
pass matching settings to `Client.make`.

Named mutations enforce Origin and CSRF before side effects, including local
calls from application routes. Raw strategy methods are treated as mutations.
For a custom credential-producing workflow, call `http.protect(effect)` inside
the request boundary; it applies mutation policy and supplies private collectors
without imposing a body format. Custom hosts still own webhook validation and
ordinary application mutation policy.

## Declare an action

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

See the [passkey contract](../guide/passkeys#define-the-shared-actions) for a complete
example and [TOTP](../guide/totp#expose-private-reveals-over-http) for private reveals.

## Lower-level transports

`http.withRequest` wraps a custom Effect returning `HttpServerResponse`.
`http.operationLayer` supplies browser policy and caller resolution to existing
`OperationHttpServer` contracts. Those descriptors continue to own private payload
injection and explicitly selected reveals.
Encode expected response failures before leaving the request wrapper.

`OperationHttpClient.make` requires the same Effect `HttpClient` service.
`OperationHttpClient.layer(options)` provides `OperationHttpClient.Client` for
consumers such as `AuthAtom.makeLifetime({ initialSubject })`. Supply this Layer
at the application boundary and keep the lifetime's Scope open until the host
finishes. The lifetime acquires its transport from the service environment.
`AuthAtom.query`, `AuthAtom.mutation`, and `AuthAtom.workflow` remain available for
custom integration. Private reveals belong in a finite
collector, outside ordinary query caches, logs, and persisted client state.
