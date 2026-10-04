---
"@yielded/auth": minor
"@yielded/auth-persistence": minor
"@yielded/auth-persistence-drizzle": minor
"@yielded/oauth": minor
---

Move Auth cryptography and OAuth/OIDC onto first-party Effect packages while preserving stored password, TOTP, and OAuth envelope formats. BEHAVIOR CHANGE: use Auth's direct service Layers and `OpenIdConnect`/`GitHub` modules with explicit crypto and HTTP services; set managed storage's `prefix` explicitly, pass Effect Crypto to `Adapter.makeStorageMappings`, and wrap application-owned Durable Object Drizzle databases with `SqliteDo.makeDatabase` for asynchronous transactions.
