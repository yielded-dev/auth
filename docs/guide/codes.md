---
description: Send email codes, verify them, and finish sign-in.
---

# Email codes and magic links

Email sign-in is a short flow: bind the request, send a proof, verify it, then
complete sign-in.

This guide shows local service calls inside existing Effect request handlers.
Provide `AppAuth` and the HTTP request boundary. For browser access, declare the
actions in a [shared contract](./http-and-client#expose-another-method).

## Enable email codes

```ts [auth.ts]
import { Schema } from "effect";
import { Auth, Sessions } from "@yielded/auth";
import { Email } from "@yielded/auth/strategies";

import { proofKeys, proofPolicy } from "./auth-config";

export const AppAuth = Auth.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: {
    email: Email.makeCode({
      template: "sign-in-code",
      digits: 6,
      keys: proofKeys,
      policy: proofPolicy,
    }),
  },
  defaultStrategy: "email",
});
```

`proofKeys` is your secret-managed proof keyring. Set expiry and attempt limits
in `proofPolicy`; its full shape is shown below.

## Start the flow and send a code

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const started = yield* auth.beginSignIn({ flowId });
```

The next request sends the code:

<!-- prettier-ignore -->
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
Your `EmailProofDelivery` service sends the code.

`requestBinding` and the continuation `credential` below are private server inputs.
Map them to the `request-binding` and `proof-continuation` slots through the
contract's `requestFields`. The resulting named server and client methods omit
those fields; never make the browser read an HttpOnly cookie or send it as JSON.

## Verify the code

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const verified = yield* auth.verifySignIn({
  flowId,
  requestBinding,
  email,
  reference,
  secret: code,
  returnTarget: "/account",
});
```

Keep `verified.continuation.continuationId`. Its matching credential is
privately delivered to the originating client.

## Complete sign-in

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.completeSignIn({
  flowId,
  requestBinding,
  email,
  continuationId,
  credential,
  returnTarget: "/account",
});
```

Check `result.completion._tag` before granting access. Only `Authenticated`
contains a session. The [HTTP adapter](./http-and-client) maps private credentials
to cookies so they stay out of ordinary browser payloads.

## Use a magic link instead

```ts [magic-link.ts]
import { Email } from "@yielded/auth/strategies";

import { proofPolicy } from "./auth-config";

export const magicLink = Email.makeLink({
  template: "sign-in-link",
  policy: proofPolicy,
});
```

Use this strategy with the same begin → request → verify → complete flow.
`makeMagicLinkRenderer` places the secret in the URL fragment. A landing-page GET
must not consume it: show a confirmation action, clear the fragment from browser
history, and complete from the originating client.

<details>
<summary>Proof expiry and rate limits</summary>

```ts [proof-policy.ts]
import type { ProofPolicy } from "@yielded/auth/Proofs";

export const proofPolicy: ProofPolicy = {
  lifetimeMillis: 5 * 60_000,
  continuationLifetimeMillis: 30_000,
  maximumFailedAttempts: 5,
  maximumDeliveryAttempts: 1,
  deliveryClaimMillis: 10_000,
  deliveryRetryMillis: 30_000,
  requestRetentionMillis: 60 * 60_000,
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

Choose the action-wide limits for your application's traffic. Resending or changing
flow IDs must not reset account-level attempt budgets.

</details>

## Supply the services

Lookup, claims, storage, and delivery are application-supplied. The library provides
an exact-route allowlist helper, Web Crypto, and empty lifecycle hooks:

```ts [email-live.ts]
import { Layer } from "effect";
import { Email } from "@yielded/auth/strategies";
import { EmailProofDelivery } from "@yielded/auth/Proofs";

import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { lookupEmail, resolveEmailClaims } from "./auth-accounts";
import { ProofPersistenceLive } from "./auth-persistence";
import { emailVendor, sendEmail } from "./email";

export const EmailLive = Layer.mergeAll(
  ProofPersistenceLive,
  Layer.succeed(Email.EmailSignInTargets, { lookup: lookupEmail }),
  Layer.succeed(AppAuth.strategies.email.ClaimsForEmail, { resolve: resolveEmailClaims }),
  Email.EmailReturnTargets.exactRoutes(["/account"]),
  EmailProofDelivery.layer(emailVendor, sendEmail),
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(EmailLive),
  Layer.provide(AuthDependencies),
);
```

The relative imports are your application modules. `sendEmail` returns a
`ProofDeliveryOutcome`; `emailVendor` declares your sender's ID and deduplication
interval (`0` when unsupported). `AuthDependencies` supplies the shared
[session, account, and key configuration](../reference/adapters#compose-the-application-layer).
For database-backed lookup, use [the email adapter](../reference/adapters#email).

For new accounts use `Email.makeRegistration`; for verified-address management
use `Email.makeAddresses`. Verification alone does not sign in or link an account.
See [email persistence](../reference/adapters#email) for those transaction boundaries.

See the [combined login example](./oauth#email-and-social-login)
to share Auth, sessions, and client methods with GitHub.
