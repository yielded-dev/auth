---
title: Sessions
description: Configure session lifetimes, read a session, and sign out.
---

Configure sessions on `Auth.make`. Request-aware methods handle credential lookup
and delivery through the [HTTP boundary](./http-and-client).

## Configure sessions

```ts title="auth.ts"
import { Schema } from "effect";
import { Auth, Sessions } from "@yielded/auth";

export const AppAuth = Auth.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful({
    idleTimeout: "30 minutes",
    maxAge: "7 days",
    renewAfter: "5 minutes",
  }),
});
```

This service only reads and manages sessions. Supply its bound
`AppAuth.sessions.StatefulSessionPersistence` and `SessionRepository` through your
storage Layer. It does not require authentication or provisioning authority.
Adding an authentication strategy also selects the default completion authority;
your account Layer supplies `AuthenticationAuthority` for issuing sessions.

| Configuration                                  | How it verifies                               | Sign-out                                                      |
| ---------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------- |
| `Sessions.stateful(options)`                   | Checks the stored session.                    | Revokes through persistence.                                  |
| `Sessions.stateless({ keys, ...options })`     | Verifies a signed token.                      | Clears this client only; existing tokens retain their expiry. |
| `Sessions.stateAssisted({ keys, ...options })` | Verifies a signed token and current validity. | Uses `SignedSessionValidity` for immediate invalidation.      |

Signed modes require an explicit keyring. Defaults are a seven-day idle timeout,
thirty-day maximum age, and renewal after one day; shorter lifetimes bound the
idle and renewal intervals. Issuer and audience default to the stable session
namespace, generation to `1`, and the token limit to `4096` bytes. After reducing
`maxAge`, retain `maximumIssuedAge` for the lifetime of previously issued tokens.

## Read the current session

Inside an existing Effect handler covered by `http.middleware`:

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const session = yield* auth.getSession();
```

The method reads the incoming session credential from `Auth.AuthRequest`. Missing,
invalid, or expired credentials return `null`. An unavailable session store,
defect, or interruption remains a failure. No cookie parsing or catch handler is
needed in application code.

Use `yield* auth.requireSession()` when a handler requires authentication; it fails
with `AuthenticationRequired` for an anonymous request. Outside a request, use
`auth.verifySession(redactedCredential)` to verify an explicit credential without
delivery requirements.

## Sign out

In the same request context, call the service directly:

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.signOut();
```

Sign-out reads the incoming credential without first verifying it and clears the
client cookie through private delivery. Its result reports `revoked`,
`already-invalid`, `client-only`, or `SessionSignOutUnavailable`. Local clearing
is not proof of server revocation; do not report global sign-out after a storage
failure. [Mounting the auth routes](./http-and-client#configure-the-server) supplies
request context and cookie delivery.

## Renew a session

Call `yield* auth.renewSession()` to renew explicitly. `getSession()` and
`requireSession()` never silently rotate credentials. Renewal delivers a
replacement credential through the same request boundary.

## Session lifecycle

```text
verify password / passkey / provider
  → approve current account and credential revision
  → commit session
  → deliver cookie
  → return public session
```

## Custom completion and additional factors

Omit `sessions` from `Auth.make` when supplying custom session/completion Layers.
The lower-level `AppAuth.sessions.statefulLayer`, `statelessLayer`, and
`stateAssistedLayer` constructors remain available for runtime-selected policy.

Configure `completionLayer({ pendingLifetimeMillis, attemptLimit })` with
`PendingAuthentication` persistence to support a second factor. A pending proof
is not an authenticated session. [TOTP](./totp) shows the complete Layer setup.

`SessionStrategy.inspect` returns private provenance for authorization decisions;
ordinary verification results omit it. Step-up binds its challenge to the source
session and credential revision and rechecks both before replacing the session.
