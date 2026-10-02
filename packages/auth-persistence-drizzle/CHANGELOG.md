# @yielded/auth-persistence-drizzle

## 0.1.0-beta.13

### Patch Changes

- [#59](https://github.com/yielded-dev/auth/pull/59) [`1c4df1c`](https://github.com/yielded-dev/auth/commit/1c4df1c52668d64b5e3d909cd03a025e88966e6a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Release password admission after attempt retention, page phone admission cleanup, and resolve an OAuth reservation when the provider issues no token.

  Keep request resources and post-commit hooks on the caller, report password outages as unavailable, and reuse each issuer's JWKS cache.

  BEHAVIOR CHANGE: Clear unresolved reservations left by earlier definite provider rejections if a cohort stays blocked. Password attempts need no reset.

- Updated dependencies [[`1c4df1c`](https://github.com/yielded-dev/auth/commit/1c4df1c52668d64b5e3d909cd03a025e88966e6a), [`1081d5b`](https://github.com/yielded-dev/auth/commit/1081d5b4003e9819e412c753273344ad00d47fc2)]:
  - @yielded/auth@0.1.0-beta.13
  - @yielded/auth-persistence@0.1.0-beta.13
  - @yielded/auth-crypto@0.1.0-beta.13

## 0.1.0-beta.12

### Minor Changes

- [#56](https://github.com/yielded-dev/auth/pull/56) [`67c8eff`](https://github.com/yielded-dev/auth/commit/67c8effd7b61ffb677e2a151d320ac308649fd12) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Acquire database, transport, credential-store, and private-output dependencies through Effect services. BEHAVIOR CHANGE: provide each Drizzle driver's `Database` through `databaseLayer` and call its factories with mappings only; provide `Current*Sql` or `NativeDatabase` when acquiring shared Adapter services; select client stores by service key, provide `OperationHttpClient.Client` to `AuthAtom.makeLifetime(options)`, and supply OpenID fetch overrides through `FetchHttpClient.Fetch`.

### Patch Changes

- Align all public packages on a single beta version and release them together.

- Updated dependencies [[`67c8eff`](https://github.com/yielded-dev/auth/commit/67c8effd7b61ffb677e2a151d320ac308649fd12)]:
  - @yielded/auth@0.1.0-beta.12
  - @yielded/auth-crypto@0.1.0-beta.12
  - @yielded/auth-persistence@0.1.0-beta.12

## 0.1.0-beta.1

### Minor Changes

- [#43](https://github.com/yielded-dev/auth/pull/43) [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Consolidate password, email, and session authentication on `Auth.make` and the strategy modules, and remove the superseded workflows, HTTP/RPC integration, OAuth linking service, and store adapters. Replace Cloudflare OTP delivery with `layerEmailProofDelivery` for the shared proof engine.

  BEHAVIOR CHANGE: Replace `PasswordAuth`, `EmailOtp`, `AuthSession`, `Workflows`, `HttpServer`, and their support services with the current strategies, `Sessions`, `Http`, and `AuthPersistence`; use `OAuth.makeAccounts` / `OAuth.makeConnected` for provider linking and access. Retired challenge, registration, OAuth-state records, and session cookies are incompatible; reset only that development state and reauthenticate, and explicitly import application identities and credentials if keeping existing accounts.

- [#45](https://github.com/yielded-dev/auth/pull/45) [`156f0b3`](https://github.com/yielded-dev/auth/commit/156f0b3b01a60bb21f9984d6d464d05f73b79283) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Retain provider access through `OAuth.make({ access: profile })` with shared Auth sessions, grant storage, refresh, and disconnect; remove OAuthApp and its separate persistence adapter.

  BEHAVIOR CHANGE: Reset development OAuthApp cookies/flows/grants and older connected token envelopes, then configure the shared sign-in and connected services; preserve account identities and outstanding reconciliation receipts.

### Patch Changes

- [#52](https://github.com/yielded-dev/auth/pull/52) [`4dbe837`](https://github.com/yielded-dev/auth/commit/4dbe837e23399e1e659c3b6eb7d2a041b5653de0) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Require stable Effect and matching SQL drivers, and update Cloudflare integration to effect-cf 0.53. Support Drizzle RC4 with the temporary Drizzle patch CLI when adding Drizzle to an existing Bun app.

- Updated dependencies [[`b9967b8`](https://github.com/yielded-dev/auth/commit/b9967b8326404a72fc5378c268ae019c4999ef0f), [`75cd72c`](https://github.com/yielded-dev/auth/commit/75cd72c41a3fecdd5c8e84cc76f2dd534b7f2e78), [`9392e50`](https://github.com/yielded-dev/auth/commit/9392e50f2b5ae7b275390fbbbd7a3100855441e4), [`bc112cc`](https://github.com/yielded-dev/auth/commit/bc112ccb9f063e374c40dc12d634efaba6812502), [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e), [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e), [`4dbe837`](https://github.com/yielded-dev/auth/commit/4dbe837e23399e1e659c3b6eb7d2a041b5653de0), [`156f0b3`](https://github.com/yielded-dev/auth/commit/156f0b3b01a60bb21f9984d6d464d05f73b79283)]:
  - @yielded/auth@0.1.0-beta.11
  - @yielded/auth-persistence@0.1.0-beta.11
  - @yielded/auth-crypto@0.1.0-beta.1

## 0.1.0-beta.0

### Minor Changes

- [#38](https://github.com/yielded-dev/auth/pull/38) [`a0e201b`](https://github.com/yielded-dev/auth/commit/a0e201be286400fc8ae310cfe5e60b5cd2c0077e) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Move Drizzle persistence and migration helpers into `@yielded/auth-persistence-drizzle`, leaving the default SQL package free of Drizzle dependencies and declarations.

  BEHAVIOR CHANGE: Import mappings from the companion root and drivers from explicit modules such as `@yielded/auth-persistence-drizzle/SqliteBun` instead of `@yielded/auth-persistence/drizzle/*`.

### Patch Changes

- Updated dependencies [[`1253846`](https://github.com/yielded-dev/auth/commit/12538461669ff3921f9a582b2ec4905f499db726), [`39bfccb`](https://github.com/yielded-dev/auth/commit/39bfccb93d9a14108b0973694e799f70f26a40fe), [`a0e201b`](https://github.com/yielded-dev/auth/commit/a0e201be286400fc8ae310cfe5e60b5cd2c0077e)]:
  - @yielded/auth@0.1.0-beta.10
  - @yielded/auth-persistence@0.1.0-beta.10
  - @yielded/auth-crypto@0.1.0-beta.0
