---
description: Begin a passkey ceremony, call the browser, and verify the response.
---

# Passkeys

Passkey sign-in has three steps: create the challenge on your server, ask the
browser to authenticate, and verify the response on your server.

## Define the shared actions

<!-- #region passkey-contract -->

```ts [passkey-contract.ts]
import { Schema } from "effect";
import { AuthContract, PasskeyContract } from "@yielded/auth/contracts";

export const PasskeyApi = AuthContract.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  actions: (sessions) => {
    const passkey = PasskeyContract.make("app/Auth/passkey", sessions);

    return {
      signIn: AuthContract.fromOperation(passkey.operations.Begin, { strategy: "passkey" }),
      completeSignIn: AuthContract.fromOperation(passkey.operations.Complete, {
        strategy: "passkey",
        requestFields: { bindingCredential: "request-binding" },
        subject: {
          fromSuccess: (result) =>
            result._tag === "Authenticated" ? result.session.subjectId : undefined,
        },
      }),
    };
  },
});
```

<!-- #endregion passkey-contract -->

`requestFields` supplies the private request binder from the HTTP request. Neither
the named server call nor the browser payload includes that credential. The
`subject` projection lets the client publish an account change after authentication.

## Enable passkeys

```ts [auth.ts]
import { Auth, Sessions } from "@yielded/auth";
import { Passkey } from "@yielded/auth/strategies";

import { PasskeyApi } from "./passkey-contract";

export const AppAuth = Auth.make(PasskeyApi, {
  sessions: Sessions.stateful(),
  strategies: {
    passkey: Passkey.make({
      relyingParty: {
        id: "app.example.com",
        name: "My app",
        origins: ["https://app.example.com"],
      },
    }),
  },
  defaultStrategy: "passkey",
});
```

Use your actual relying-party ID and exact allowed origins. Changing these can
make existing passkeys unusable.

## Begin sign-in on the server

Inside an existing Effect handler, with `AppAuth` provided and the HTTP request
boundary in place:

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const started = yield* auth.signIn({ flowId, commandId, profileId: "default" });
```

Return the challenge to the browser. The request-binding credential is delivered
privately; keep it associated with this flow.

## Ask the browser to authenticate

Inside a scoped browser Effect, import `makeSimpleWebAuthnPasskeyBrowser` from
`@yielded/auth/PasskeyBrowser` and use the public `started` result:

<!-- prettier-ignore -->
```ts
const browser = yield* makeSimpleWebAuthnPasskeyBrowser();
const assertion = yield* browser.authenticate({ started, mediation: "required" });
```

Keep the Effect's Scope open for the ceremony. Interrupting it cancels that
ceremony. Import `PasskeyBrowser` only in the browser; it requires
`@simplewebauthn/browser`.

## Complete sign-in on the server

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.completeSignIn({ flowId, response });
```

Here `response` is the serialized string obtained from
`Redacted.value(assertion.response)` in the browser ceremony above, with `Redacted`
imported from `effect`. Send it through the protected transport; the server injects
the original request-binding cookie. A session
is issued only after server verification and the current account checks succeed.
The client exposes the same calls as `client.auth.signIn(...)` and
`client.auth.completeSignIn(...)`. The
[Atom workflow](./http-and-client#compose-a-passkey-workflow) connects these steps.

## Install the server verifier

```ts [passkey-protocol.ts]
import { layerSimpleWebAuthnPasskeyProtocol } from "@yielded/auth/PasskeySimpleWebAuthn";

export const PasskeyProtocolLive = layerSimpleWebAuthnPasskeyProtocol({
  profiles: [
    {
      profileId: "default",
      generation: 1,
      rpId: "app.example.com",
      rpName: "My app",
      origins: ["https://app.example.com"],
      developmentLocalhost: false,
      residentKey: "required",
      userVerification: "required",
      primarySignIn: true,
      attestation: "none",
      algorithms: [-7, -257],
    },
  ],
});
```

Provide this Layer with your passkey persistence, account/claims services, and
session configuration. Install its `@simplewebauthn/server` and `tldts` peers.
Keep the verifier profile consistent with the method's relying-party configuration.

## Registration and management

| Task                                   | Strategy and methods                                                               |
| -------------------------------------- | ---------------------------------------------------------------------------------- |
| Create an account with a passkey       | `Passkey.makeRegistration` → `register`, `completeRegistration`.                   |
| Add, list, rename, or remove a passkey | `Passkey.makeManagement` and its authenticated operations.                         |
| Confirm a protected password change    | `@yielded/auth/PasskeyPassword` binds the assertion to a prepared password intent. |

These require explicit application authority. A registration ceremony must not
silently become a login ceremony or link an existing account. See
[passkey persistence](../reference/adapters#passkeys) for transaction ownership.
