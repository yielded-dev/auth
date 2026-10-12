---
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Validate physical schemas independently with `Persistence.validate` or `OAuthPersistence.validate(mapping)`. Use `{ validation: "skip" }` after deployment validation to build request-scoped persistence without runtime catalog queries.
