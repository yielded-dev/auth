---
"@yielded/auth": minor
---

Add opt-in OpenID application scopes, resource audiences, signed access tokens, and rotating refresh grants that recheck application authorization while preserving the original authentication time; existing defaults retain opaque UserInfo access without refresh grants.
Expose public-key access verification and infer middleware, authorization, and verified access scopes from native scope schemas.

BEHAVIOR CHANGE: Declare server scopes with `Schema.Literals([...])` instead of an array, and pass the schema as `scopes`.
