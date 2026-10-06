---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Reduce stateful session checks to one SQL statement, add opt-in signed cookie caching with fresh session reads, and share one root KV Layer across session validity and rate limiting.

BEHAVIOR CHANGE: Provide signed-session keys through `Sessions.SessionSigningKeys`, include `session-cache` in custom credential-slot mappings, declare custom validity-adapter consistency, and account for cache or eventual revocation windows in invalidation policies.
