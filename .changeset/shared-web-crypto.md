---
"@yielded/auth": patch
"@yielded/crypto": minor
---

Use crypto's scoped HMAC keys and web adapters for Auth session signatures and numeric proofs without changing credential formats.

BEHAVIOR CHANGE: Implement scoped `importKey` in custom `Hmac` services, replace Auth `SubtleCrypto` overrides with an `Hmac` Layer, and keep direct session/numeric-proof crypto constructors in an open Scope; existing Auth web Layer exports remain available.
