# @yielded/auth-crypto

## 0.1.0-beta.2

### Patch Changes

- Updated dependencies [[`67c8eff`](https://github.com/yielded-dev/auth/commit/67c8effd7b61ffb677e2a151d320ac308649fd12)]:
  - @yielded/auth@0.1.0-beta.12

## 0.1.0-beta.1

### Patch Changes

- [#52](https://github.com/yielded-dev/auth/pull/52) [`4dbe837`](https://github.com/yielded-dev/auth/commit/4dbe837e23399e1e659c3b6eb7d2a041b5653de0) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Require stable Effect and matching SQL drivers, and update Cloudflare integration to effect-cf 0.53. Support Drizzle RC4 with the temporary Drizzle patch CLI when adding Drizzle to an existing Bun app.

- Updated dependencies [[`b9967b8`](https://github.com/yielded-dev/auth/commit/b9967b8326404a72fc5378c268ae019c4999ef0f), [`75cd72c`](https://github.com/yielded-dev/auth/commit/75cd72c41a3fecdd5c8e84cc76f2dd534b7f2e78), [`9392e50`](https://github.com/yielded-dev/auth/commit/9392e50f2b5ae7b275390fbbbd7a3100855441e4), [`bc112cc`](https://github.com/yielded-dev/auth/commit/bc112ccb9f063e374c40dc12d634efaba6812502), [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e), [`4973533`](https://github.com/yielded-dev/auth/commit/49735334149d3d29a34542047a27ff6fffac9f7e), [`4dbe837`](https://github.com/yielded-dev/auth/commit/4dbe837e23399e1e659c3b6eb7d2a041b5653de0), [`156f0b3`](https://github.com/yielded-dev/auth/commit/156f0b3b01a60bb21f9984d6d464d05f73b79283)]:
  - @yielded/auth@0.1.0-beta.11

## 0.1.0-beta.0

### Minor Changes

- [#36](https://github.com/yielded-dev/auth/pull/36) [`1253846`](https://github.com/yielded-dev/auth/commit/12538461669ff3921f9a582b2ec4905f499db726) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Move maintained cryptography into `@yielded/auth-crypto`, leaving Effect as core's only runtime peer and preserving stored credential and ciphertext formats. BEHAVIOR CHANGE: supply password hashing, TOTP cryptography, and OAuth protector Layers from the companion package; move `digest`/`randomId` and TOTP crypto helper imports there, and provide OAuthApp protectors instead of passing `transactionKeys`/`tokenKeys` options.

### Patch Changes

- Updated dependencies [[`1253846`](https://github.com/yielded-dev/auth/commit/12538461669ff3921f9a582b2ec4905f499db726), [`39bfccb`](https://github.com/yielded-dev/auth/commit/39bfccb93d9a14108b0973694e799f70f26a40fe)]:
  - @yielded/auth@0.1.0-beta.10
