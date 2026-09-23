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
package. Both packages release at the same version. Platform, browser, and OAuth adapters have separate exports.
The root import does not load their peer dependencies. Effect is supplied by the host.

See the [authentication guide](https://github.com/yielded-dev/auth/blob/main/docs/guide/authentication.md)
and [consumer examples](https://github.com/yielded-dev/auth/tree/main/examples/auth).
