# @yielded/auth-platform-workerd

## 0.1.0-beta.48

### Patch Changes

- Updated dependencies [[`e2705d9`](https://github.com/yielded-dev/auth/commit/e2705d950d6213f8befc8e07ed59c400b3869393), [`b8a94df`](https://github.com/yielded-dev/auth/commit/b8a94df51121c90fc712012f33f05128f4fba4dc), [`058d118`](https://github.com/yielded-dev/auth/commit/058d118b6386cedaa1e3ec30b140bd19c44692b3), [`adbd95f`](https://github.com/yielded-dev/auth/commit/adbd95f01409c8130487391857f38f0bc639021f)]:
  - @yielded/auth@0.1.0-beta.48

## 0.1.0-beta.47

### Minor Changes

- [#288](https://github.com/yielded-dev/auth/pull/288) [`109c420`](https://github.com/yielded-dev/auth/commit/109c4201e63637c8e9c23039c5a248b872fddca0) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Use Effect crypto and one `WebCrypto.layer` preset, and move Workers password hashing to `@yielded/auth-platform-workerd`. BEHAVIOR CHANGE: require Effect 4.1 and matching SQL drivers; replace `@yielded/crypto` and Auth's Workers subpaths with Effect crypto Layers or the Workers package, supply HTTP and the Kdf for `Testing.services()` separately, and use `Password.KdfAdmission.layer()`, optional `PasswordScrypt.layer`, and opaque Effect keys for JOSE.

### Patch Changes

- Updated dependencies [[`197ddba`](https://github.com/yielded-dev/auth/commit/197ddba9395e4622c0d4dd0b8cb769b8d6364a78), [`1dd5bbe`](https://github.com/yielded-dev/auth/commit/1dd5bbe219733a0f09614c2e3b2520f62bdb421f), [`b0b5df2`](https://github.com/yielded-dev/auth/commit/b0b5df2d405bcbc70a04b4391763f16aed10f9e1), [`109c420`](https://github.com/yielded-dev/auth/commit/109c4201e63637c8e9c23039c5a248b872fddca0)]:
  - @yielded/auth@0.1.0-beta.47
