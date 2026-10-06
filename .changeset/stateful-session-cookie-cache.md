---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Add opt-in stateful session cookie caching with bounded staleness, authoritative fresh reads, and diagnostics for cache failures.

BEHAVIOR CHANGE: Provide signing keys through `Sessions.SessionSigningKeys`, supply `getSessionFresh` to AuthAtom clients and reserve `freshSession`, handle `cache-expiry` invalidation windows, and include `session-cache` in custom credential-slot and native-header mappings.
