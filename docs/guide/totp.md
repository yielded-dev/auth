---
description: Enroll an authenticator and complete sign-in with a second factor.
---

# Two-factor authentication

Add `Totp` alongside a primary method. It supports authenticator codes and
single-use recovery codes. The local calls below belong inside existing Effect
request handlers, with `AppAuth` and the HTTP request boundary provided.

## Enable the authenticator

```ts [auth.ts]
import { Schema } from "effect";
import { Auth, Password, Totp } from "@yielded/auth";

export const AppAuth = Auth.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  strategies: {
    password: Password.make(),
    totp: Totp.make({
      issuer: "My app",
      enrollmentLifetimeMillis: 5 * 60_000,
      revealLifetimeMillis: 60_000,
      clockSkewSteps: 1,
      attemptLimit: 5,
      attemptWindowMillis: 5 * 60_000,
      maximumEvidenceAgeMillis: 60_000,
      allowRecoveryCodeForPending: true,
      lostFactorRecovery: "deny",
      requireImmediateInvalidation: true,
    }),
  },
  defaultStrategy: "password",
});
```

Your `AuthenticationAuthority` decides which accounts require two factors.
Provide `TotpPersistence`, `TotpSecretKeys`, `TotpActionEvidence`, and stateful
sessions with pending-authentication support. This definition omits `sessions`
so you can supply the custom completion Layer below to `AppAuth.layer`.

```ts [sessions.ts]
import { Layer } from "effect";

import { AppAuth } from "./auth";
import { sessionPolicy } from "./auth-config";

export const SessionsLive = AppAuth.sessions
  .completionLayer({
    pendingLifetimeMillis: 5 * 60_000,
    attemptLimit: 5,
  })
  .pipe(Layer.provideMerge(AppAuth.sessions.statefulLayer(sessionPolicy)));
```

Supply your stateful session store, `PendingAuthentication` store, authentication
authority, crypto, and hooks to this Layer. A correct password can then produce a
pending proof instead of failing when a second factor is required.

## Begin enrollment

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.beginEnrollment("totp", { commandId, accountName, actionProof });
```

This requires an authenticated caller and fresh action evidence from your
`TotpActionEvidence` service, bound to the exact command. `actionProof` is that
independent evidence; a session cookie is not a substitute. The public result
contains the enrollment ID. The secret and provisioning URI are delivered through
a temporary `totp-enrollment` reveal for your QR-code screen.

## Confirm the first code

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.confirmEnrollment("totp", {
  commandId,
  enrollmentId,
  code,
  actionProof,
});
```

Show the private `recovery-codes` reveal once and let the user save it. Keep both
reveals out of ordinary query caches, logs, and persisted UI state.

## Finish a two-factor sign-in

For this local method, `pendingCredential` is the private proof issued by the
primary method. The shared action below injects it from the request cookie.

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.verifyPending("totp", { pendingCredential, code });
```

```text
password accepted
  → pending proof cookie (not a session)
  → authenticator code
  → verifyPending
  → consume pending proof + issue session
```

Use `auth.recoverPending("totp", { pendingCredential, code })` for a recovery
code. Each code is consumed once. A replay or exhausted attempt budget fails closed.

## Expose private reveals over HTTP

Use the pure TOTP contracts to add named actions:

```ts [totp-contract.ts]
import { Schema } from "effect";
import * as AuthContract from "@yielded/auth/AuthContract";
import * as TotpContract from "@yielded/auth/TotpContract";

export const TotpApi = AuthContract.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  actions: (sessions) => {
    const totp = TotpContract.make("app/Auth/totp", sessions);

    return {
      signIn: AuthContract.passwordSignIn(sessions),
      beginEnrollment: AuthContract.fromOperation(totp.operations.Begin, {
        strategy: "totp",
      }),
      confirmEnrollment: AuthContract.fromOperation(totp.operations.Confirm, {
        strategy: "totp",
      }),
      verifyPending: AuthContract.fromOperation(totp.operations.VerifyPending, {
        strategy: "totp",
        requestFields: { pendingCredential: "pending-proof" },
        subject: {
          fromSuccess: (result) =>
            result._tag === "Authenticated" ? result.session.subjectId : undefined,
        },
      }),
    };
  },
});
```

In the server definition above, replace `"app/Auth"` with `TotpApi` and remove
`claims`, which now belongs to the contract. Keep the same strategies and custom
session Layer. Mount it with `Http.layer(AppAuth, options)` as in the
[HTTP guide](./http-and-client#configure-the-server).

The named methods select the TOTP strategy and inject the pending cookie, so the
server call becomes `auth.verifyPending({ code })` and the client call becomes
`client.auth.verifyPending({ code })`. Enrollment still takes fresh `actionProof`;
there is deliberately no mapping from the session cookie to that field.

`fromOperation` carries forward the `totp-enrollment` and `recovery-codes` reveal
declarations. Configure `Client.make` with a `privateOutput` collector that supports
those kinds and implements `accept` and `clear`. Give the collector a finite
lifetime, erase expired reveals, and clear it when the enrollment screen closes.
The client also clears it on account transition and disposal. Keep reveals outside
ordinary atom results, query caches, logs, and persisted client state.
