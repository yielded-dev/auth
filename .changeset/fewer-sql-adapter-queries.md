---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Reduce database roundtrips for authentication, credential management, and cleanup, including single-query passkey lookup with compatible mapped references. Keep SQLite cleanup batches within Durable Object statement limits.
