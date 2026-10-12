---
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Preserve request-local SQL connection providers during composed persistence initialization. Validate physical schemas independently with `Persistence.validate` or `OAuthPersistence.validate(mapping)`, and use `{ validation: "skip" }` to avoid runtime catalog queries.
