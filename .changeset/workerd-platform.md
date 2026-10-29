---
"@yielded/auth": patch
"@yielded/auth-platform-workerd": minor
"@yielded/auth-persistence": patch
---

Move Workers runtime services and WASM Argon2id into `@yielded/auth-platform-workerd`; use its root for passwords and `/Passwordless` for crypto and HTTP alone. BEHAVIOR CHANGE: replace Auth's Workers subpaths with this package and supply an Effect Kdf Layer to `Testing.services()`.
