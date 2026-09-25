# @yielded/auth-react-native

Client-local iOS passkey registration, authentication, and capability checks for
`@yielded/auth`. Import `* as ReactNativePasskey` from this package and construct
the adapter with `ReactNativePasskey.make()`, or provide `ReactNativePasskey.layer`.

Install this package and its `react-native` and `react-native-passkey` peers only
in the native application. `@yielded/auth` does not depend on React Native or
this adapter. The adapter consumes core's public passkey schemas and returns the
same flow IDs and redacted completion responses as the browser adapter.

Applications own begin → prompt → complete, HTTP, binding, persistence, sessions,
and associated domains. Registration creates ES256 platform passkeys; authentication
also supports existing security-key credentials. iOS 16+ is supported; Android and
conditional mediation are unsupported. Interruption discards delivery but cannot dismiss the system
prompt, and the shared busy guard stays held until the native promise settles.

See the [iOS setup guide](../../docs/guide/passkeys.md#prompt-in-an-ios-react-native-app)
and [API reference](../../docs/reference/passkey-react-native.md).
