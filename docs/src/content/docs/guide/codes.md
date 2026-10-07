---
title: Email codes and magic links
description: Send an email code and redeem it to sign in.
---

Email sign-in has three steps: bind the request, send a proof, then submit its
reference and secret to complete sign-in.

This guide shows local service calls inside existing Effect request handlers.
Provide `AppAuth` and the HTTP request boundary. For browser access, declare the
actions in a [shared contract](./http-and-client#expose-another-method).

## Enable email codes

```ts title="apps/server/auth.ts"
import { Schema } from "effect";
import { Auth, Email, Sessions } from "@yielded/auth";

export const AppAuth = Auth.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: {
    email: Email.makeCode(),
  },
  defaultStrategy: "email",
});
```

Codes default to six digits and five minutes. Override `digits` or `policy` when
needed. Supply shared `ProofKeys` through [AuthDependencies](../reference/adapters#compose-the-application-layer).

## Start the flow and send a code

```ts
const auth = yield* AppAuth;
const started = yield* auth.beginSignIn({ flowId });
```

The next request sends the code:

```ts
const auth = yield* AppAuth;
const sent = yield* auth.signIn({
  flowId,
  requestId,
  requestBinding,
  email,
  returnTarget: "/account",
  locale: "en",
});
```

`beginSignIn` delivers a private request-binding credential. The next request uses
that credential as `requestBinding`. `signIn` returns a proof `reference`, not the code.
Auth renders the email; your `EmailDelivery` service sends the finished message.

`requestBinding` is a private server input. Map it to the `request-binding` slot
through the contract's `requestFields`; named client methods then omit it.
Never make the browser read an HttpOnly cookie or send it as JSON.

## Complete sign-in

```ts
const auth = yield* AppAuth;
const result = yield* auth.completeSignIn({
  flowId,
  requestBinding,
  email,
  reference,
  secret: code,
  returnTarget: "/account",
});
```

Check `result.completion._tag` before granting access. Only `Authenticated`
contains a session. The proof is consumed before independent session issuance; if
issuance fails or its outcome is unknown, start a new flow. The [HTTP adapter](./http-and-client) maps private credentials
to cookies so they stay out of ordinary browser payloads.

## Use a magic link instead

```ts title="apps/server/magic-link.ts"
import { Email } from "@yielded/auth";

export const magicLink = Email.makeLink({ url: "https://app.example.com/sign-in" });
```

Use this strategy with the same begin → request → complete flow.
Auth places the reference and secret in the URL fragment. Use
`EmailDelivery.parseLinkFragment` to read it. A landing-page GET
must not consume it: show a confirmation action, clear the fragment from browser
history, and complete from the originating client.

<details id="proof-expiry-and-rate-limits">
<summary>Proof expiry and rate limits</summary>

```ts title="apps/server/proof-policy.ts"
import { type Proofs } from "@yielded/auth";

export const proofPolicy: Proofs.ProofPolicy = {
  lifetimeMillis: 5 * 60_000,
  maximumFailedAttempts: 5,
  abuse: {
    issues: { limit: 5, windowMillis: 60 * 60_000 },
    attempts: { limit: 10, windowMillis: 5 * 60_000 },
    subjectIssues: { limit: 5, windowMillis: 60 * 60_000 },
    subjectAttempts: { limit: 10, windowMillis: 5 * 60_000 },
    actionIssues: { limit: 1000, windowMillis: 60 * 60_000 },
    actionAttempts: { limit: 1000, windowMillis: 5 * 60_000 },
    resendCooldownMillis: 30_000,
  },
};
```

Every issue request and candidate attempt spends action, identifier, and known-subject
token buckets for schema-valid requests, including suppressed or repeated issuance,
unknown targets, and malformed candidate secrets. Host ingress separately limits
schema-invalid requests.
Auth's default `ProofLimiter` retains at most 10,000 active buckets and fails closed
at capacity. It is process-local; supply a shared Effect `RateLimiterStore` across
replicas. Host ingress separately limits traffic before target lookup.

Request again with the original binding after `resendCooldownMillis` to issue a new
code. `requestId` is correlation only and does not recover an earlier receipt.
Each new code starts with zero failed attempts; an old code never spends its
replacement's failure allowance. Successful redemption deletes the code, so only
the limiter bounds subsequent issuance. Expired-code cleanup preserves the durable
cooldown because cooldown must be shorter than the code lifetime.

A live, unexpired proof can be replaced only with the same complete request
binding. Knowing its public reference does not grant replacement authority.
A different flow may need to wait for expiry; host ingress limits unsolicited
requests but cannot guarantee availability against distributed traffic.

</details>

## Supply the services

Your application supplies lookup, claims, storage, delivery, and
[crypto Layers](../reference/crypto#use-with-auth). Auth provides request rate
limiting, a delivery worker, an exact-route allowlist helper, and empty lifecycle hooks:

```ts title="apps/server/email-live.ts"
import { Layer } from "effect";
import { Email } from "@yielded/auth";

import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { lookupEmail, resolveEmailClaims } from "./auth-accounts";
import { ProofPersistenceLive } from "./auth-persistence";
import { EmailLive } from "./email";

export const EmailServicesLive = Layer.mergeAll(
  ProofPersistenceLive,
  Layer.succeed(Email.EmailSignInTargets, { lookup: lookupEmail }),
  Layer.succeed(AppAuth.strategies.email.SessionClaims, { resolve: resolveEmailClaims }),
  Email.EmailReturnTargets.exactRoutes(["/account"]),
  EmailLive,
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(EmailServicesLive),
  Layer.provide(AuthDependencies),
);
```

For sibling apps, configure [cross-origin return targets](./http-and-client#sharing-sessions-across-apps).

The relative imports are your application modules. `EmailLive` implements the
email service. Auth's built-in worker keeps provider acceptance outside the request's
wait for a response; build Auth in an application scope that outlives requests.
See [email delivery](./email-delivery#compose-auth) for runtime ownership and overrides.
`AuthDependencies` supplies the shared
[session, account, and key configuration](../reference/adapters#compose-the-application-layer).
For database-backed lookup, use [the email adapter](../reference/adapters#email).

Email requests check the built-in rate limiter before target lookup,
including repeated requests and unknown addresses. HTTP derives the caller from the
socket peer automatically. See [HTTP admission](./http-and-client#proof-request-admission)
for configuration and overrides.

## Register a mailbox owner

Compose `Email.makeRegistration({ namespace, registration: Registration })` with
`Email.makeCode({ namespace })` using the same namespace. A guest calls
`beginRegistration` → `register` → `completeRegistration`.
The [shared login contract](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-contract.ts)
exposes these existing operations with a private request-binding cookie; the [server composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-server.ts)
supplies both strategies.

Provide the registration strategy's `RegistrationAuthority` with
`makeEmailRegistrationServices` from your Drizzle adapter, and provide
`ProofPersistence` through `makeProofPersistenceServices` with the same proof mapping
for issuance and redemption. Completed mailbox proof can replace another subject's active, unverified email reservation
when the application's inspection and proof policies allow it. The new account
receives the verified address. The earlier account keeps its data and credentials,
and its security revision advances. Verified ownership is never replaced.

Registration does not issue a session. Start a fresh email sign-in afterward;
an authenticated user can then call `addPassword` when password management is
enabled. `AuthPersistence.layer` does not install guest email-registration services
automatically. Provisioning completes synchronously using the authority's stable
`requestId`, derived from the redeemed proof;
applications whose accounts live elsewhere can own a queue before registration. See [email persistence](../reference/adapters#email) for mapping
and session invalidation requirements.

Use `Email.makeAddresses` for authenticated address management. Confirming an
address there does not create or link an account.

See the [combined login example](./oauth#other-providers)
to share Auth, sessions, and client methods with GitHub.
