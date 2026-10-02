# @yielded/auth-react-native

Client-local iOS passkeys and browser login for `@yielded/auth`. Applications own
authentication workflows, HTTP, sessions, and native application configuration.
Core has no React Native dependency. Both adapters require iOS 16+; Android is
unsupported.

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

```sh
bun add @yielded/auth-react-native@beta effect react-native-inappbrowser-reborn react-native-keychain
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

An Expo 57 app can use [`expo-crypto`](https://docs.expo.dev/versions/v57.0.0/sdk/crypto/)
(SDK-compatible range `~57.0.3`) in its own `native-crypto.ts`:

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

`layerBrowser` uses the maintained
[`react-native-inappbrowser-reborn`](https://github.com/proyecto26/react-native-inappbrowser)
bridge's `openAuth` API, backed by `ASWebAuthenticationSession`. Register a reverse-domain
custom URL scheme in `CFBundleURLTypes`, for example `com.example.app`, and register
the exact return URL, such as `com.example.app://auth/callback`, with your server.
The hosted page must use HTTPS. This bridge does not support HTTPS universal-link
callbacks. Core checks state and codes; the adapter checks the full callback target.
Do not reopen the returned URL with `Linking.openURL`.

Each `open` owns its prompt Scope. Interruption requests `closeAuth`, discards late
results, and retains the process-wide busy guard until the native promise settles.
All callers must use this adapter's single installed bridge instance. The
`ephemeral` option requests a browser session without shared browsing data; it
does not revoke sessions or clear the vault.

`layerVault` stores the private attempt and credential slots together through
[`react-native-keychain`](https://oblador.github.io/react-native-keychain/docs/usage/).
Items use `WHEN_UNLOCKED_THIS_DEVICE_ONLY` with cloud synchronization disabled.
Use a unique `service` per app, server environment, and client ID; acquire one
vault Layer per authentication lifetime, without other writers to that service.
Keychain writes are not cancellable: admitted operations settle before releasing
the vault's serialization gate. The bridge does not supply a transactional or
cross-process compare-and-set guarantee; failures never authorize an exchange retry.

Core owns restoring `Waiting`, persisting `Exchanging` before dispatch, and refusing
to repeat that exchange. The vault preserves either phase without replaying it;
`saveAttempt(undefined)` clears only the attempt. Expired credentials are omitted
from reads. Corrupt or inaccessible storage fails closed. Credential methods retain
`OperationHttpError`; attempt methods use `BrowserLogin.PlatformError`. Neither
exposes native messages or private values in errors.

Keychain data can survive app deletion; uninstalling is not a reliable reset.
Keep credentials and attempts out of React state, logs, and public operation
results. Provide the vault as the native credentials service to the shared HTTP
client. Verify the chosen React Native transport's redirect rejection and cookie
omission on device before treating an end-to-end flow as proven.

Use a signed physical-device build to verify the prompt, registered callback,
Keychain persistence across relaunch, and cancellation. A simulator or mocked
bridge alone does not establish those outcomes.
