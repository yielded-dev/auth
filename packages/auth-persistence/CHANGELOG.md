# @yielded/auth-persistence

## 0.1.0-beta.7

### Minor Changes

- [#26](https://github.com/yielded-dev/auth/pull/26) [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Move SQL adapters into `@yielded/auth-persistence` and add managed schemas, opt-in Layers for Drizzle Kit migrations, and direct Effect SQL persistence for password registration and recovery, email verification, phone sign-in, and stateful sessions.

  BEHAVIOR CHANGE: Import Drizzle adapters from `@yielded/auth-persistence/drizzle/*`; both packages now release together at the same version.

### Patch Changes

- [#26](https://github.com/yielded-dev/auth/pull/26) [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add a runnable account example with application-declared Drizzle tables and Drizzle Kit migrations, including email verification and passkeys.

- [#26](https://github.com/yielded-dev/auth/pull/26) [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Preserve existing sessions when confirming an already-bound, unverified email address, and let application policy accept its valid session evidence. Omit `invalidation` from that completion result; retain recent-authentication and invalidation requirements when adding or replacing an address.

- [#26](https://github.com/yielded-dev/auth/pull/26) [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Preserve existing authentication when adding a passkey and allow application-defined authorization freshness limits.

  BEHAVIOR CHANGE: `PasskeyEnrolled` and `PasskeyManagementPersistence.completeEnrollment` no longer include `invalidation`; custom persistence must preserve the subject security revision during enrollment.

- [#26](https://github.com/yielded-dev/auth/pull/26) [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Compose Drizzle passkey sign-in and management storage from the Auth definition, with opt-in managed tables and migrations.

  BEHAVIOR CHANGE: Return Effects from `write.policy.requirement` and `write.policy.remainingSignIn` in explicit passkey mappings, for example `() => Effect.succeed(requirement)`.

- [#26](https://github.com/yielded-dev/auth/pull/26) [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Complete direct Effect SQL support for email verification and passkey sign-in and management. Add a runnable account example with application-owned SQLite or PostgreSQL migrations, email verification, recovery, and passkeys.

- Updated dependencies [[`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3), [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3), [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3), [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3), [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3), [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3), [`5ccfe5a`](https://github.com/yielded-dev/auth/commit/5ccfe5a26e15351ff0b19b0199b858a9e22b889c), [`d1f2799`](https://github.com/yielded-dev/auth/commit/d1f279964029ac25e7a58dc6fe8ca29025bd4bd3), [`57427ef`](https://github.com/yielded-dev/auth/commit/57427ef4c086fa66a519c80944a24fa6c53d0885)]:
  - @yielded/auth@0.1.0-beta.7
