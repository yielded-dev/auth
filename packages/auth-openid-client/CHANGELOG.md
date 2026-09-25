# @yielded/auth-openid-client

## 0.1.0-beta.0

### Minor Changes

- [#35](https://github.com/yielded-dev/auth/pull/35) [`39bfccb`](https://github.com/yielded-dev/auth/commit/39bfccb93d9a14108b0973694e799f70f26a40fe) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Move SimpleWebAuthn, OpenID Client, GitHub, and Cloudflare integrations into companion packages, removing their SDK dependencies from core. BEHAVIOR CHANGE: import them from `@yielded/auth-simplewebauthn/Browser` or `/Server` (using `make` and `layer`), `@yielded/auth-openid-client` or its `/Connected` and `/GitHub` entries, and `@yielded/auth-cloudflare`.

### Patch Changes

- Updated dependencies [[`1253846`](https://github.com/yielded-dev/auth/commit/12538461669ff3921f9a582b2ec4905f499db726), [`39bfccb`](https://github.com/yielded-dev/auth/commit/39bfccb93d9a14108b0973694e799f70f26a40fe)]:
  - @yielded/auth@0.1.0-beta.10
