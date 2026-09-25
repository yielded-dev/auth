# @yielded/auth

Composable authentication workflows for Effect applications: sign-in, sessions,
OAuth, passwords, passkeys, email and phone proofs, and TOTP.

```sh
vp add @yielded/auth@beta effect@4.0.0-rc.117
```

The package owns security-sensitive workflow contracts. Applications own identity,
persistence, protocol verification, and delivery adapters. Resources live in the
caller’s Scope; credentials stay outside public results and telemetry.

SQL adapters and managed storage live in the companion `@yielded/auth-persistence`
package. Both packages release at the same version. SDK integrations live in `@yielded/auth-simplewebauthn`,
`@yielded/auth-openid-client`, and `@yielded/auth-cloudflare`. Core does not import
these packages or declare their SDK peers. Effect is its only runtime peer.
Supply password hashing and OAuth/TOTP secret protection through the maintained
`@yielded/auth-crypto` Layers or your own implementations of the core services.

See the [authentication guide](https://github.com/yielded-dev/auth/blob/main/docs/guide/authentication.md)
and [consumer examples](https://github.com/yielded-dev/auth/tree/main/examples/auth).
