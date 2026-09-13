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

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const started = yield* auth.signIn({ phoneNumber, locale: "en" });
```

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

| Service                                   | Responsibility                                |
| ----------------------------------------- | --------------------------------------------- |
| `PhoneSignInTargets`                      | Look up your existing phone credential.       |
| `PhoneDeliveryEligibility`                | Apply country and delivery policy.            |
| `SmsProofDelivery`                        | Send the code.                                |
| `ProofPersistence`                        | Enforce expiry, consumption, and rate limits. |
| `AppAuth.strategies.phone.ClaimsForPhone` | Build session claims.                         |

Phone registration and number changes use separate lifecycle operations.
Do not link accounts because their supplied phone strings match. See the
[phone application composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-application.ts).
