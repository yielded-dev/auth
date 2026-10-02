# @yielded/auth-cloudflare

## 0.1.0-beta.2

### Patch Changes

- Updated dependencies [[`67c8eff`](https://github.com/yielded-dev/auth/commit/67c8effd7b61ffb677e2a151d320ac308649fd12)]:
  - @yielded/auth@0.1.0-beta.12

## 0.1.0-beta.1

### Minor Changes

- [#43](https://github.com/yielded-dev/auth/pull/43) [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Consolidate password, email, and session authentication on `Auth.make` and the strategy modules, and remove the superseded workflows, HTTP/RPC integration, OAuth linking service, and store adapters. Replace Cloudflare OTP delivery with `layerEmailProofDelivery` for the shared proof engine.

  BEHAVIOR CHANGE: Replace `PasswordAuth`, `EmailOtp`, `AuthSession`, `Workflows`, `HttpServer`, and their support services with the current strategies, `Sessions`, `Http`, and `AuthPersistence`; use `OAuth.makeAccounts` / `OAuth.makeConnected` for provider linking and access. Retired challenge, registration, OAuth-state records, and session cookies are incompatible; reset only that development state and reauthenticate, and explicitly import application identities and credentials if keeping existing accounts.

### Patch Changes

- [#52](https://github.com/yielded-dev/auth/pull/52) [`4dbe837`](https://github.com/yielded-dev/auth/commit/4dbe837e23399e1e659c3b6eb7d2a041b5653de0) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Require stable Effect and matching SQL drivers, and update Cloudflare integration to effect-cf 0.53. Support Drizzle RC4 with the temporary Drizzle patch CLI when adding Drizzle to an existing Bun app.

- Updated dependencies [[`b9967b8`](https://github.com/yielded-dev/auth/commit/b9967b8326404a72fc5378c268ae019c4999ef0f), [`75cd72c`](https://github.com/yielded-dev/auth/commit/75cd72c41a3fecdd5c8e84cc76f2dd534b7f2e78), [`9392e50`](https://github.com/yielded-dev/auth/commit/9392e50f2b5ae7b275390fbbbd7a3100855441e4), [`bc112cc`](https://github.com/yielded-dev/auth/commit/bc112ccb9f063e374c40dc12d634efaba6812502), [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e), [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e), [`4dbe837`](https://github.com/yielded-dev/auth/commit/4dbe837e23399e1e659c3b6eb7d2a041b5653de0), [`156f0b3`](https://github.com/yielded-dev/auth/commit/156f0b3b01a60bb21f9984d6d464d05f73b79283)]:
  - @yielded/auth@0.1.0-beta.11

## 0.1.0-beta.0

### Minor Changes

- [#35](https://github.com/yielded-dev/auth/pull/35) [`39bfccb`](https://github.com/yielded-dev/auth/commit/39bfccb93d9a14108b0973694e799f70f26a40fe) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Move SimpleWebAuthn, OpenID Client, GitHub, and Cloudflare integrations into companion packages, removing their SDK dependencies from core. BEHAVIOR CHANGE: import them from `@yielded/auth-simplewebauthn/Browser` or `/Server` (using `make` and `layer`), `@yielded/auth-openid-client` or its `/Connected` and `/GitHub` entries, and `@yielded/auth-cloudflare`.

### Patch Changes

- Updated dependencies [[`1253846`](https://github.com/yielded-dev/auth/commit/12538461669ff3921f9a582b2ec4905f499db726), [`39bfccb`](https://github.com/yielded-dev/auth/commit/39bfccb93d9a14108b0973694e799f70f26a40fe)]:
  - @yielded/auth@0.1.0-beta.10
