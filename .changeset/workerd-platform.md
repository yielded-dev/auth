---
"@yielded/auth": patch
"@yielded/auth-platform-workerd": minor
"@yielded/auth-persistence": patch
---

Move Workers runtime services and WASM Argon2id into `@yielded/auth-platform-workerd`. BEHAVIOR CHANGE: replace Auth's Workers subpaths with this package, replace `@yielded/auth/WebCrypto` with Effect's crypto Layers, and supply an Effect Kdf Layer to `Testing.services()`.
