# @yielded/auth

Composable authentication workflows for Effect applications: sign-in, sessions,
OAuth, passwords, passkeys, email and phone proofs, and TOTP.

```sh
bun add @yielded/auth@beta effect
```

The package owns authentication workflows and native OAuth/OIDC verification.
Applications own identity, persistence, keys, policy, and private delivery.
Resources live in the caller’s Scope; credentials stay outside public results
and telemetry. Runtime dependencies are Effect and the first-party
`@yielded/crypto` and `@yielded/oauth` packages.

Supply `Password.PasswordHashing.layer()`, `Totp.TotpCryptography.layer`, and the
OAuth protector services’ `.layer(keyring)` defaults with owned crypto services
and Effect `Crypto`. Keys remain application-owned. Password hashing requires
`Kdf` and `PasswordKdfAdmission`; build one `PasswordKdfAdmission.layer()` instance
and share its two service tags with the crypto backend and all hashers. Its permit
covers parsing, derivation, comparison, and cleanup. If increasing password work
limits, configure the supplied KDF backend to permit those same limits.

`OpenIdConnect.provider` and `GitHub.provider` configure native providers for the
HTTP host; their `layer` and `layerConnected` constructors supply the protocol
services directly. Construction requires an explicit nonretrying, nonredirecting
Effect `HttpClient`, Effect `Crypto`, and owned `Signature`/`Hmac` services.
Provider clients and JOSE caches belong to the construction Scope. Keep that Scope
open throughout use, and retain retired credential generations while issued flows
or connected grants still reference them. Unknown exchange outcomes never authorize
repeating an exchange.

SQL adapters live in `@yielded/auth-persistence`. Optional WebAuthn SDK integration
lives in `@yielded/auth-simplewebauthn`. Email delivery uses the application’s
`EmailDelivery` service; Auth renders the private message before handing it off.

Start with the [setup guide](https://yielded.dev/auth/guide/getting-started/),
or read [how authentication fits together](https://yielded.dev/auth/guide/authentication/).
