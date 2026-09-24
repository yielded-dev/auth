# @yielded/auth-persistence

## 0.1.0-beta.9

### Minor Changes

- [#32](https://github.com/yielded-dev/auth/pull/32) [`85b10e7`](https://github.com/yielded-dev/auth/commit/85b10e7ee3c90d45721d7cbbc5125e30d8645167) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add OAuth authorization for registered MCP clients with browser consent, PKCE, scoped tokens, refresh rotation, and revocation. Protect Effect MCP routes with request authentication and persist grants through the standalone SQL adapter.

### Patch Changes

- [#30](https://github.com/yielded-dev/auth/pull/30) [`81b98eb`](https://github.com/yielded-dev/auth/commit/81b98eb6c7b046813d05a343697b460978f7d3df) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Require Effect 4.0.0-rc.117, matching SQL drivers, and effect-cf 0.49.0 for Cloudflare integrations. Accept safe PostgreSQL `bigint` values in raw SQL mappings, release nested MySQL savepoints, and reject standalone persistence operations inside ambient libSQL transactions.

- Updated dependencies [[`81b98eb`](https://github.com/yielded-dev/auth/commit/81b98eb6c7b046813d05a343697b460978f7d3df), [`85b10e7`](https://github.com/yielded-dev/auth/commit/85b10e7ee3c90d45721d7cbbc5125e30d8645167)]:
  - @yielded/auth@0.1.0-beta.9

## 0.1.0-beta.8

### Minor Changes

- [#28](https://github.com/yielded-dev/auth/pull/28) [`9f88281`](https://github.com/yielded-dev/auth/commit/9f8828130424b45f8f74d462a4aac524e22511f2) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add managed OAuth sign-in that retains provider access and issues stateless application sessions, with GitHub and Strava adapters and SQL storage.
  Allow HTTP loopback callbacks for local OAuth development while requiring HTTPS for provider endpoints.

### Patch Changes

- Updated dependencies [[`9f88281`](https://github.com/yielded-dev/auth/commit/9f8828130424b45f8f74d462a4aac524e22511f2)]:
  - @yielded/auth@0.1.0-beta.8

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
