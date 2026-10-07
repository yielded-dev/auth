---
"@yielded/auth": patch
"@yielded/auth-persistence": minor
"@yielded/auth-persistence-drizzle": patch
---

Reduce database roundtrips for authentication, credential management, and cleanup, including single-query passkey lookup with compatible mapped references. Keep SQLite cleanup batches within Durable Object statement limits.

BEHAVIOR CHANGE: Custom adapters using `@yielded/auth-persistence/Adapter` must implement the shared workflow capabilities; generic query-kernel builders and shared SQL transaction services have been removed.
