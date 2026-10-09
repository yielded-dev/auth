---
title: Passwords
description: Register accounts, sign in, and change passwords.
---

Use `Password.make()` for existing-account sign-in. Configure registration and
recovery to enable full password management.

## Enable passwords

```ts title="apps/server/auth.ts"
import { Schema } from "effect";
import { Auth, Password, Sessions } from "@yielded/auth";

export const AppAuth = Auth.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: {
    password: Password.make({
      registration: Schema.Struct({ displayName: Schema.NonEmptyString }),
      reset: Password.resetLink({ url: "https://app.example.com/reset-password" }),
    }),
  },
  defaultStrategy: "password",
});
```

Password policy and proof expiry have defaults. Choose reset links or codes explicitly.
Your application controls account creation and supplies an email transport. For sign-in only, use
`password: Password.make()` as in [getting started](./getting-started).

This definition exposes local methods. The calls below belong inside an existing
Effect request handler, with `AppAuth` provided and the HTTP request boundary in
place. To expose methods to a browser, declare them in the
[shared contract](./http-and-client#define-the-routes); enabling registration or
reset support does not automatically publish those endpoints.

## Register an account

```ts
const auth = yield* AppAuth;
const result = yield* auth.register({
  requestId,
  email,
  newPassword,
  registration: { displayName },
});
```

Generate `requestId` once per submission and retain it for an exact retry.
`RegistrationAccepted` does not reveal whether the account already existed.
Provisioning completes synchronously. If accounts live in another system, provision
idempotently by `requestId` or run an application-owned queue before registration.

Password registration does not prove ownership of the email address. Offer
[mailbox registration](./codes#register-a-mailbox-owner) with `Email.makeRegistration`
so the mailbox owner can complete signup when someone else reserved the address
without verifying it. This provisions a fresh account; it does not reset or inherit
the earlier account. Password-only compositions must add that registration endpoint
and its services explicitly.

## Handle a rejected sign-in

With `Effect` imported from `effect`, handle only the expected rejection:

```ts
const auth = yield* AppAuth;
const result = yield* auth.signIn({ email, password }).pipe(
  Effect.catchTag("PasswordRejected", () =>
    Effect.succeed({ _tag: "InvalidCredentials" as const }),
  ),
);
```

Use the same message for a missing account and a wrong password. Storage and
hashing failures remain errors; do not turn them into successful sign-ins.
An `Authenticated` result carries the session; an additional-factor result
must be completed before granting access.

## Change a password

```ts
const auth = yield* AppAuth;
const result = yield* auth.changePassword({ commandId, currentPassword, newPassword });
```

This call requires an authenticated `Auth.AuthRequest`. Applications requiring
another factor supply `actionProof` or accept recent session step-up through
`PasswordActionEvidence`. A passkey step-up can authorize the change without
`currentPassword`; check authentication age and the actual fresh private passkey
proof obtained through `sessions.inspectInvocation`. Public `invocation.assurance`
describes the session but cannot supply credential IDs or replace that proof.
Current authority is checked again at commit.
The result reports the session invalidation behavior of your selected strategy.
After passkey authentication, the application can call:

```ts
const result = yield* auth.changePassword({ commandId, newPassword });
```

## Supply the services

Supply `Password.PasswordHashing.layer()` with an explicit crypto backend,
bounded KDF admission, and Effect Crypto for entropy. Storage, claims, account
creation, screening, and change authorization remain application-owned:

```ts title="apps/server/password-live.ts"
import { Layer } from "effect";
import { Password } from "@yielded/auth";

import { AppAuth } from "./auth";
import { CryptoLive } from "./crypto-live";
import { AuthDependencies } from "./auth-dependencies";
import { authorizePasswordChange, registerAccount, resolvePasswordClaims } from "./auth-accounts";
import { PasswordPersistenceLive, ProofPersistenceLive } from "./auth-persistence";
import { checkPassword } from "./password-screening";
import { EmailLive } from "./email";

export const PasswordLive = Layer.mergeAll(
  Password.PasswordHashing.layer().pipe(Layer.provide(CryptoLive)),
  PasswordPersistenceLive,
  ProofPersistenceLive,
  Layer.succeed(AppAuth.strategies.password.SessionClaims, { resolve: resolvePasswordClaims }),
  Layer.succeed(AppAuth.strategies.password.RegistrationAuthority, { register: registerAccount }),
  Layer.succeed(Password.CompromisedPasswords, { check: checkPassword }),
  Layer.succeed(Password.PasswordActionEvidence, { verify: authorizePasswordChange }),
  EmailLive,
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(PasswordLive),
  Layer.provide(AuthDependencies),
);
```

The relative imports are your application modules; [Drizzle adapters](../reference/adapters#passwords)
can provide persistence and registration. `AuthDependencies` supplies the shared
[session, account, and key configuration](../reference/adapters#compose-the-application-layer).
For sign-in-only `Password.make()`, supply hashing, password persistence, and claims
alongside those shared services. Keep normalization stable for stored credentials.

[`CryptoLive`](../reference/crypto#use-with-auth) is the shared application crypto
Layer. Install `@yielded/crypto` alongside Auth when importing its backend. See
[crypto backends](../reference/crypto#compose-a-backend) for native alternatives.
Share one `KdfAdmission.layer()` from `@yielded/crypto/KdfAdmission` across hashers
and backends in each runtime. `Layer.provideMerge(Admission)` exposes that service. The outer password operation and nested derivations use
that same instance; comparison and secret cleanup retain the permit. Nested work
in the same fiber reuses it, while child fibers acquire independently.
By default it runs one KDF callback and accepts up to 16 waiting calls, each with a
5000ms acquisition deadline. A full queue or expired wait fails with
`PasswordKdfBusy`; interrupted waiters leave the queue. Once admitted to run, work
retains its permit through completion and cleanup, even if its caller is interrupted.
The deadline does not limit running KDF work.

Configure `concurrency`, `maxQueued`, and `maxWaitMilliseconds` on the Layer;
`maxQueued: 0` enables fail-fast admission. Size concurrency for your host's KDF
memory and CPU budget. These are process-local limits, without a strict FIFO
ordering guarantee; applications still need ingress rate limits.

Password verification also consumes action, identifier, and known-subject budgets
through `Password.PasswordAttemptLimiter`. These token buckets allow an initial
burst and refill at `limit / windowMillis`. Consumption happens before verification
and is never refunded, even if verification is interrupted or fails.
A store failure denies the request.

The default store is process-local and resets on restart. Its fixed capacity is
10,000 keys, shared by action, identifier, and subject buckets across every module
using that store. Raising action limits or lengthening identifier/subject windows
does not increase capacity. A full store returns `PasswordUnavailable` for requests
needing a new key, including valid accounts; existing buckets keep their limits.
High traffic or many distinct identifiers can exhaust this capacity.

When full, the store reclaims buckets idle for a complete refill window, including
time since their last rejected check. Active buckets are never evicted and no
background cleanup fiber runs. Before increasing budgets, provide a store sized
for the resulting active keys. The password attempt policy controls bucket sizes;
KDF concurrency remains a separate service.

### Share rate limits

The default only protects a long-lived process. Each instance keeps its own counts,
and a runtime built per request, such as a Worker that creates Auth on each fetch,
keeps none: the limits never trigger. Supply one shared Effect `RateLimiterStore`
and every auth limiter uses it: passwords, codes, phone, passkeys, and host ingress. Action, global message, and passkey module budgets always stay
per instance; shared, one key would take every request's write and let any client
exhaust everyone's allowance.

`keyValueRateLimiterStore` keeps buckets in any Effect `KeyValueStore`, keyed by a
SHA-256 digest, so entries fit KV's key limits and store no identifiers. It uses
the Auth runtime's `Crypto` service. With Workers KV:

```ts
import { Effect, Layer } from "effect";
import { KeyValueStore } from "effect/persistence";
import { keyValueRateLimiterStore } from "@yielded/auth/Persistence";

const workersKv = (kv: KVNamespace) => {
  const call = <A>(method: string, run: () => Promise<A>) =>
    Effect.tryPromise({
      try: run,
      catch: (cause) =>
        new KeyValueStore.KeyValueStoreError({ method, message: "Workers KV failed", cause }),
    });

  return KeyValueStore.makeStringOnly({
    get: (key) => call("get", async () => (await kv.get(key)) ?? undefined),
    // At least the longest limit window; idle buckets refill when next read.
    set: (key, value) => call("set", () => kv.put(key, value, { expirationTtl: 3600 })),
    remove: (key) => call("remove", () => kv.delete(key)),
    clear: call("clear", () => Promise.reject(new Error("unsupported"))),
    size: call("size", () => Promise.reject(new Error("unsupported"))),
  });
};

export const RateLimitsLive = (kv: KVNamespace) =>
  keyValueRateLimiterStore.pipe(
    Layer.provide(Layer.succeed(KeyValueStore.KeyValueStore, workersKv(kv))),
  );
```

Provide `RateLimitsLive(env.RATE_LIMITS)` to your Auth Layer. Each check reads and
writes one entry without atomicity, so concurrent requests and KV replication can
admit a few extra attempts; a read or write failure denies the request. For exact
limits, supply an atomic store such as `RateLimiter.layerStoreRedis()`.

Sign-in reads the credential and captures authority before hashing, then checks
current account status, credential revisions, and factor policy again when issuing
a session. No password attempt row or direct sign-in flow row is stored. Rehashing
writes only when hash parameters change, with a comparison that cannot overwrite a
newer password. Pending second factors retain their own single-use state; password
changes use the original authority and credential revisions without a command receipt.

Compromised-password screening fails closed. `PasswordPolicy.screeningTimeoutMillis`
defaults to 10,000 ms (allowed range: 1–30,000); a timed-out check returns
`PasswordCheckUnavailable`, so no password is registered or changed.

### Native scrypt on Workers

Choose the scrypt configuration and the Workers backend at the composition root:

```ts
import { Password } from "@yielded/auth";
import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import * as WorkerdCrypto from "@yielded/crypto/platform-workerd";
import * as WebCrypto from "@yielded/crypto/WebCrypto";
import { Layer } from "effect";

const Admission = KdfAdmission.layer();
const CryptoLive = Layer.merge(
  WebCrypto.layerCryptoWeb,
  WorkerdCrypto.layer(globalThis.crypto.subtle).pipe(Layer.provideMerge(Admission)),
);
const PasswordHashingLive = Password.PasswordHashing.layer(
  Password.defaultScryptPasswordHashingConfig,
).pipe(Layer.provide(CryptoLive));
```

This uses native `node:crypto.scrypt` with `N=16384`, `r=8`, `p=5`: the
[OWASP 16 MiB profile](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt).
Node and Bun backends support the same configuration. The package ships ordinary
JavaScript; Workers must enable Node.js compatibility.

New hashes store their parameters as `$scrypt$ln=14,r=8,p=5$<salt>$<hash>`.
Existing Argon2id and PBKDF2 hashes remain verifiable and are rehashed through the
existing conditional persistence update after successful sign-in. That first
sign-in pays both verification and rehash costs. Stored password normalization
does not change. Keep a backend that can verify both algorithms during migration.

`PasswordHashing.layer()` still defaults to Argon2id. Supplying `scrypt` in
`PasswordHashingConfig` selects scrypt for new hashes and dummy attempts. Its
supported costs are 8192, 16384, and 32768, with `r=8` and at least 10, 5, and 3
parallelization steps respectively. Verification also enforces the configured
memory and work ceilings before deriving a key.

## Recover a password

Recovery uses `requestReset` → `completeReset` and requires an
independently verified email address. Users who have a passkey sign in with it,
complete step-up if required, then change their password. The definition above selects reset links.
Auth builds the link and renders the email; your `EmailDelivery` service only
sends the finished message. See [email delivery](./email-delivery) for REST API
and Alchemy examples.

The link destination must be a fixed HTTPS URL without credentials, query, or
fragment. Auth validates it when building the Layer, before issuing any proof.
For a code-entry UI, select numeric codes instead:

```ts
Password.make({
  registration: Schema.Struct({ displayName: Schema.NonEmptyString }),
  reset: Password.resetCode(),
});
```

Codes default to six digits and also require `Proofs.ProofKeys.layer(proofKeys)` in
[`AuthDependencies`](../reference/adapters#compose-the-application-layer). Keep
leading zeroes by treating codes as strings. Link proofs do not require that keyring.
Both choices have working default email content; wording and localization can be
customized independently of the transport.

Start recovery inside an Effect request handler:

```ts
const auth = yield* AppAuth;
const requested = yield* auth.requestReset({ flowId, requestId, email, locale: "en" });
```

Retain the original flow ID, email, request ID, and reference. Always show a generic
response such as “If this address is eligible, check your email.” The receipt does
not reveal account eligibility or whether a message was sent.

To resend, retain the flow ID and use a fresh request ID after the cooldown.
A request with that same complete binding replaces the previous code when the
cooldown permits it. Another binding cannot replace an unexpired code. Suppressed
requests do not extend its expiry (five minutes by default).

Auth supplies a network rate limiter, and HTTP derives the caller from the socket
peer automatically. Checks precede target lookup, including unknown addresses and
retries. See [HTTP admission](./http-and-client#proof-request-admission) for overrides and
[proof budgets](./codes#proof-expiry-and-rate-limits) for delivery limits.

For links, the originating client uses `EmailDelivery.parseLinkFragment` to extract
the reference and secret, clears the fragment from history, then waits for an
intentional confirmation before submitting. A landing-page GET must never consume
the proof. See [link handling](./email-delivery#handle-links) for the private-state
and response-header boundaries. For codes, use the saved reference and entered code.

Submit the reference, secret, and replacement together:

```ts
const auth = yield* AppAuth;
const result = yield* auth.completeReset({
  flowId,
  email,
  commandId,
  newPassword,
  reference,
  secret,
});
```

Generate `commandId` once per submission. Hashing and independent action policy run
before storage locks. The mutation owner rechecks current authority, redeems the
proof, and replaces the password atomically; a protected-write failure rolls back
redemption. Completion changes the password; sign in separately for a session.
Never return secrets in ordinary operation results or logs.

### Delivery and retry boundaries

Auth's built-in worker admits delivery after the proof commits, so public requests
do not wait for provider acceptance. No scheduler setup is needed; build Auth in an
application scope that outlives requests, as shown in [email delivery](./email-delivery#compose-auth).
Work may start before the response is sent. Application hooks and persistence can
still vary in latency.

Provider acceptance does not prove inbox delivery. Each confirmed issuance submits
one private delivery task and invokes the transport at most once in that process.
There is no dispatch retry or durable outbox; queue rejection, interruption, or a
crash can leave a code unsent. Unknown commit outcomes never schedule delivery.
Request again explicitly after the cooldown with the original binding. The request
ID is correlation only. A consumed proof or unknown mutation outcome does not
authorize repeating a password change.

See the [complete password composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/password-methods.ts)
for a reset-link journey using a private local email collector.
