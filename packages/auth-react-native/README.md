# @yielded/auth-react-native

Client-local iOS passkeys and browser login for `@yielded/auth`. Applications own
authentication workflows, HTTP, sessions, and native application configuration.
Core has no React Native dependency. Passkeys require iOS 16+; browser login's
minimum depends on the chosen Expo SDK. Android is unsupported.

Import the package root for passkeys, or `@yielded/auth-react-native/BrowserLogin`
for browser login. Install only the optional native peers for the entrypoint you
use, autolink with CocoaPods, and rebuild the application.

## Passkeys

Import `* as ReactNativePasskey` from this package and construct the adapter with
`ReactNativePasskey.make()`, or provide `ReactNativePasskey.layer`.

Install this package and its `react-native` and `react-native-passkey` peers only
in the native application. `@yielded/auth` does not depend on React Native or
this adapter. The adapter consumes core's public passkey schemas and returns the
same flow IDs and redacted completion responses as the browser adapter.

Applications own begin → prompt → complete, HTTP, binding, persistence, sessions,
and associated domains. Registration creates ES256 platform passkeys; authentication
also supports existing security-key credentials. iOS 16+ is supported; Android and
conditional mediation are unsupported. Interruption discards delivery but cannot dismiss the system
prompt, and the shared busy guard stays held until the native promise settles.

See the [iOS setup guide](../../docs/src/content/docs/guide/passkeys.md#prompt-in-an-ios-react-native-app)
and [API reference](../../docs/src/content/docs/reference/passkey-react-native.md).

## Browser login

Use the peers matching your app's Expo SDK. SDK 54 (React Native 0.81) uses
WebBrowser `~15.0.11` and SecureStore `~15.0.8`; SDK 57 uses WebBrowser `~57.0.3`
and SecureStore `~57.0.4`. This adapter requires iOS 16+ with SDK 54 or iOS 16.4+
with SDK 57. For SDK 54:

```sh
bun add @yielded/auth-react-native@beta effect expo-web-browser@~15.0.11 expo-secure-store@~15.0.8 react-native-url-polyfill
```

Plain React Native apps must first [install Expo Modules](https://docs.expo.dev/bare/installing-expo-modules/).
Rebuild the native app after installing the peers.

Browser login requires complete WHATWG `URL` and `URLSearchParams` implementations;
React Native's built-in URL implementation is insufficient for callback validation.
Load the [URL polyfill](https://github.com/charpeni/react-native-url-polyfill) in your
application entrypoint before any auth module imports:

```ts
import "react-native-url-polyfill/auto";
import "./app";
```

Supply core's `BrowserLogin.Browser` and `BrowserLogin.Vault` with separate Layers:

```ts
import { Layer } from "effect";
import * as NativeBrowserLogin from "@yielded/auth-react-native/BrowserLogin";

export const NativeLoginLive = Layer.merge(
  NativeBrowserLogin.layerBrowser,
  NativeBrowserLogin.layerVault({ service: "com.example.app.auth.production" }),
);
```

`BrowserLogin.makeClient` also requires Effect's `Crypto.Crypto` for secure random
bytes and SHA-256. React Native does not supply browser `SubtleCrypto`; do not
provide `WebCrypto.layerWebCrypto`. Crypto belongs to the application's composition
root, alongside its native HTTP client, and is not an additional peer of this adapter.

An Expo 54 app can use [`expo-crypto`](https://docs.expo.dev/versions/v54.0.0/sdk/crypto/)
(SDK-compatible range `~15.0.9`) in its own `native-crypto.ts`:

```ts
import { Crypto, Effect, Layer, PlatformError } from "effect";
import * as ExpoCrypto from "expo-crypto";

const algorithms = {
  "SHA-1": ExpoCrypto.CryptoDigestAlgorithm.SHA1,
  "SHA-256": ExpoCrypto.CryptoDigestAlgorithm.SHA256,
  "SHA-384": ExpoCrypto.CryptoDigestAlgorithm.SHA384,
  "SHA-512": ExpoCrypto.CryptoDigestAlgorithm.SHA512,
};

const unavailable = (method: string) =>
  PlatformError.systemError({ _tag: "Unknown", module: "Crypto", method });

export const ExpoCryptoLive = Layer.sync(Crypto.Crypto, () => {
  const crypto = Crypto.make({
    randomBytes: (size) => ExpoCrypto.getRandomValues(new Uint8Array(size)),
    digest: (algorithm, data) =>
      Effect.tryPromise({
        try: async () =>
          new Uint8Array(await ExpoCrypto.digest(algorithms[algorithm], Uint8Array.from(data))),
        catch: () => unavailable("digest"),
      }),
  });

  return Crypto.Crypto.of({
    ...crypto,
    randomBytes: (size) =>
      crypto
        .randomBytes(size)
        .pipe(Effect.catchDefect(() => Effect.fail(unavailable("randomBytes")))),
  });
});
```

Provide the vault to the app's `OperationHttpClient.Client` Layer, preserving the
same instance for `BrowserLogin.makeClient`:

```ts
const NativeClientLive = NativeHttpClientLive.pipe(
  Layer.provideMerge(NativeLoginLive),
  Layer.provideMerge(ExpoCryptoLive),
);

const makeClient = BrowserLogin.makeClient(contract, options).pipe(
  Effect.provide(NativeClientLive),
);
```

Here `NativeHttpClientLive` uses `BrowserLogin.Vault` as its native credentials
service and already provides its transport. Use `getRandomValues`:
Expo documents a development `Math.random` fallback for `getRandomBytes`. The
example keeps bridge failures typed and sanitized, and passes raw digest bytes
back to core for base64url encoding. Run in the native runtime with the module
linked; a browser debugger does not prove native crypto availability.

`layerBrowser` uses [Expo WebBrowser](https://docs.expo.dev/versions/latest/sdk/webbrowser/)
and `ASWebAuthenticationSession`. Register a reverse-domain
custom URL scheme in `CFBundleURLTypes`, for example `com.example.app`, and register
the exact return URL, such as `com.example.app://auth/callback`, with your server.
Custom-scheme clients retain explicit account confirmation when reusing an
existing browser session. The hosted page must use HTTPS. Core checks state and
codes; the adapter checks the full callback target.

HTTPS callbacks require iOS 17.4+ and a signed `webcredentials:<callback-host>`
[Associated Domains entitlement](https://developer.apple.com/documentation/xcode/supporting-associated-domains).
The host's `apple-app-site-association` file must list the app's `TEAMID.bundleID`
under `webcredentials.apps`. Register that same app ID and exact callback URL on
the server before enabling its automatic SSO policy. Ordinary Universal Link
delivery additionally uses `applinks`; the authentication session receives its
callback directly. Older iOS versions fail before opening an HTTPS callback session.
Do not reopen the returned URL with `Linking.openURL` or add a competing Linking listener.

Each `open` owns its prompt Scope. Interruption requests `dismissAuthSession`, discards late
results, and retains the process-wide busy guard until the native promise settles.
All callers must use this adapter's single installed bridge instance. The
`ephemeral` option requests a browser session without shared browsing data; it
does not revoke sessions or clear the vault.
SDK 54 can leave a failed native presentation pending; interrupt the operation to
dismiss it and settle the bridge before trying again.

`layerVault` stores the private attempt and credential slots in one record through
[Expo SecureStore](https://docs.expo.dev/versions/v54.0.0/sdk/securestore/).
It uses device-only Keychain access while unlocked (`WHEN_UNLOCKED_THIS_DEVICE_ONLY`),
with biometric gating disabled (`requireAuthentication: false`). Use a fresh,
dedicated `service` per app, server environment, and client ID; acquire one vault
Layer per authentication lifetime, without other writers to that service. Keep
the service name stable across restarts.
Native writes are not cancellable: admitted operations settle before releasing
the vault's serialization gate. A failed write may have committed; failures never
authorize an exchange retry. The vault provides no cross-process compare-and-set.

Core owns restoring `Waiting`, persisting `Exchanging` before dispatch, and refusing
to repeat that exchange. The vault preserves either phase without replaying it;
`saveAttempt(undefined)` clears only the attempt. Expired credentials are omitted
from reads. Invalid JSON and native read/write errors fail closed. Credential
methods retain `OperationHttpError`; attempt methods use `BrowserLogin.PlatformError`.
Neither exposes native messages or private values in errors.

The previous experimental Keychain vault is not imported. Before switching,
reconcile any uncertain exchange and revoke the old development native session;
then reset only that app/environment/client's vault and sign in afresh.
Keychain data can survive app deletion; uninstalling is not a reliable reset.
Keep credentials and attempts out of React state, logs, and public operation
results. Provide the vault as the native credentials service to the shared HTTP
client. Verify the chosen React Native transport's redirect rejection and cookie
omission on device before treating an end-to-end flow as proven.

Use a signed physical-device build to verify the prompt, registered callback,
SecureStore persistence across relaunch and interrupted writes, and cancellation.
Verify your credential record sizes on device; native storage can reject large
values. A simulator or mocked bridge alone does not establish those outcomes.
