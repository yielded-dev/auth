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

export const AppAuth = Auth.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: {
    phone: PhoneOtp.make(),
  },
  defaultStrategy: "phone",
});
```

The default code has six digits and expires after five minutes. Override `digits`
or `policy` only to change that behavior. Keys and delivery come from Layers.

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
}).pipe(
  Effect.provideService(PhoneOtp.PhoneRequestContext, { networkKey }),
);
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
import * as Twilio from "@yielded/auth/Twilio";
import { FetchHttpClient } from "effect/unstable/http";

import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { resolvePhoneClaims } from "./auth-accounts";
import { PhonePersistenceLive, ProofPersistenceLive } from "./auth-persistence";
import { canSendSms } from "./sms";
import { TwilioConfigLive } from "./auth-config";

const SmsLive = Twilio.layer.pipe(
  Layer.provide(TwilioConfigLive),
  Layer.provide(FetchHttpClient.layer),
);

export const PhoneLive = Layer.mergeAll(
  PhonePersistenceLive,
  ProofPersistenceLive,
  Layer.succeed(PhoneOtp.PhoneDeliveryEligibility, { allowed: canSendSms }),
  Layer.succeed(AppAuth.strategies.phone.ClaimsForPhone, { resolve: resolvePhoneClaims }),
  SmsLive,
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(PhoneLive),
  Layer.provide(AuthDependencies),
);
```

The relative imports are your application modules. `PhonePersistenceLive` supplies
`PhoneSignInTargets` and `PhoneAdmission` for sign-in; see the
[Drizzle wiring](../reference/adapters#phone). `ProofPersistenceLive` supplies
`ProofPersistence`. `AuthDependencies` provides the shared
[session, account, and key configuration](../reference/adapters#compose-the-application-layer).

`canSendSms` applies your country and delivery policy; `resolvePhoneClaims` loads
session claims. `TwilioConfigLive` supplies `Twilio.TwilioConfig` with `accountSid`,
a redacted `authToken`, and either `from` or `messagingServiceSid`. It can load those
values from Effect Config or your secret store. Twilio uses Effect HTTP; no SDK is needed.

Supply another `SmsDelivery` implementation to use another vendor. Delivery is
required; omitting it leaves a TypeScript dependency error. Web Crypto and empty
lifecycle hooks have defaults. Shared `ProofKeys` come from `AuthDependencies`.

<details>
<summary>Customize the SMS message</summary>

Add this optional Layer to `PhoneLive`:

```ts
PhoneOtp.Template.layer({
  render: (code) => `Your Acme sign-in code is ${code}.`,
});
```

The default is `Your sign-in code is 123456.` The renderer also receives locale
and expiry as its second argument. Text stays private through delivery.

</details>

<details>
<summary>Register or change phone numbers</summary>

Enable lifecycle operations on the same strategy:

```ts
phone: PhoneOtp.make({ lifecycle: true });
```

Use a lifecycle policy object instead of `true` to customize its behavior.

These operations additionally require `PhonePersistence` and `PhoneActionEvidence`.
The Drizzle Layer above already supplies `PhonePersistence`. Add independent
authorization to `PhoneLive`:

```ts
Layer.succeed(PhoneOtp.PhoneActionEvidence, { verify: authorizePhoneChange });
```

`authorizePhoneChange` is your application's check of independent evidence for
a number change. Start with `auth.begin(input)` and finish with
`auth.completeLifecycle(input)`. Supply `PhoneRequestContext`
for each request, as for sign-in.

Do not link accounts because their phone strings match. See the
[complete phone composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts).

</details>
