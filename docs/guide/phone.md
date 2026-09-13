---
description: Request an SMS code and sign in with a phone number.
---

# Phone codes

Use `PhoneOtp` to sign in existing accounts with an SMS code.

The snippets below are local calls inside existing Effect request handlers, with
`AppAuth` and the HTTP request boundary provided. Publish selected methods through
a [shared contract](./http-and-client#expose-another-method) for browser clients.

## Enable phone sign-in

```ts [auth.ts]
import { Schema } from "effect";
import { Auth, Sessions } from "@yielded/auth";
import { PhoneOtp } from "@yielded/auth/strategies";

import { proofKeys } from "./auth-config";

export const AppAuth = Auth.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: {
    phone: PhoneOtp.make({
      template: "sign-in-sms",
      keys: proofKeys,
    }),
  },
  defaultStrategy: "phone",
});
```

Load `proofKeys` from your secret configuration. The default code has six digits
and expires after five minutes. You can override `digits` and `policy`.

## Send a code

With `Effect` imported from `effect`, supply the request's host-verified network key:

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const started = yield* auth.signIn({ phoneNumber, locale: "en" }).pipe(
  Effect.provideService(PhoneOtp.PhoneRequestContext, { networkKey }),
);
```

`networkKey` is a `Redacted<string>` used for admission limits. Derive it on the
server per request; the HTTP auth adapter does not supply it.
Use an international number such as `+14155550123`. The result contains a `flowId`
and proof `reference`. The request binder goes through private credential delivery;
your SMS service receives the code.

## Complete sign-in

Use the original `flowId` and `reference`. The server resolves `requestBinding`
from private request credentials. In a shared action, map it with
`requestFields: { requestBinding: "request-binding" }`; the named server and client
calls then take only the public fields.

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.completeSignIn({
  flowId,
  phoneNumber,
  requestBinding,
  reference,
  code,
});
```

```text
signIn({ phoneNumber })
  → SMS + private request binder
  → user enters code
  → completeSignIn(original flow, binder, reference, code)
  → session or additional-factor result
```

A consumed code cannot be reused if session issuance subsequently fails. Request
a new code. SMS proves possession; it does not provide phishing resistance.

## Supply the services

These services have no automatic defaults. Connect your database, account policy,
and SMS sender:

```ts [phone-live.ts]
import { Layer } from "effect";
import { PhoneOtp } from "@yielded/auth/strategies";
import { SmsProofDelivery } from "@yielded/auth/Proofs";

import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { authorizePhoneChange, resolvePhoneClaims } from "./auth-accounts";
import { PhonePersistenceLive, ProofPersistenceLive } from "./auth-persistence";
import { canSendSms, sendSms, smsVendor } from "./sms";

export const PhoneLive = Layer.mergeAll(
  PhonePersistenceLive,
  ProofPersistenceLive,
  Layer.succeed(PhoneOtp.PhoneDeliveryEligibility, { allowed: canSendSms }),
  Layer.succeed(PhoneOtp.PhoneActionEvidence, { verify: authorizePhoneChange }),
  Layer.succeed(AppAuth.strategies.phone.ClaimsForPhone, { resolve: resolvePhoneClaims }),
  SmsProofDelivery.layer(smsVendor, sendSms),
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provideMerge(PhoneLive),
  Layer.provide(AuthDependencies),
);
```

The relative imports are your application modules. `PhonePersistenceLive` supplies
`PhoneSignInTargets`, `PhonePersistence`, and `PhoneAdmission`; see the
[Drizzle wiring](../reference/adapters#phone). `ProofPersistenceLive` supplies
`ProofPersistence`. `AuthDependencies` provides the shared
[session, account, and key configuration](../reference/adapters#compose-the-application-layer).

`canSendSms` applies your country and delivery policy; `resolvePhoneClaims` loads
session claims. `sendSms` returns a `ProofDeliveryOutcome`. Set `smsVendor` to
`{ vendorId: "your-sender", idempotencyMillis: 0 }` unless your vendor guarantees
deduplication for a longer interval.

Web Crypto and empty lifecycle hooks are installed automatically.
`Layer.provideMerge` keeps phone admission services available to local calls.

Phone registration and number changes use separate lifecycle operations.
The phone definition includes their storage and `PhoneActionEvidence` requirements;
`authorizePhoneChange` must verify independent evidence for a number change.
Do not link accounts because their supplied phone strings match. See the
[complete phone composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts).
