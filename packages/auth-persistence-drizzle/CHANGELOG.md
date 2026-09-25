# @yielded/auth-persistence-drizzle

## 0.1.0-beta.0

### Minor Changes

- [#38](https://github.com/yielded-dev/auth/pull/38) [`a0e201b`](https://github.com/yielded-dev/auth/commit/a0e201be286400fc8ae310cfe5e60b5cd2c0077e) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Move Drizzle persistence and migration helpers into `@yielded/auth-persistence-drizzle`, leaving the default SQL package free of Drizzle dependencies and declarations.

  BEHAVIOR CHANGE: Import mappings from the companion root and drivers from explicit modules such as `@yielded/auth-persistence-drizzle/SqliteBun` instead of `@yielded/auth-persistence/drizzle/*`.

### Patch Changes

- Updated dependencies [[`1253846`](https://github.com/yielded-dev/auth/commit/12538461669ff3921f9a582b2ec4905f499db726), [`39bfccb`](https://github.com/yielded-dev/auth/commit/39bfccb93d9a14108b0973694e799f70f26a40fe), [`a0e201b`](https://github.com/yielded-dev/auth/commit/a0e201be286400fc8ae310cfe5e60b5cd2c0077e)]:
  - @yielded/auth@0.1.0-beta.10
  - @yielded/auth-persistence@0.1.0-beta.10
  - @yielded/auth-crypto@0.1.0-beta.0
