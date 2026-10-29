---
"@yielded/auth": patch
"@yielded/auth-platform-workerd": minor
"@yielded/auth-persistence": patch
---

Move Workers crypto services and WASM Argon2id into `@yielded/auth-platform-workerd`, and provide one portable `WebCrypto.layer` preset. BEHAVIOR CHANGE: replace Auth's Workers subpaths with this package, use `WebCrypto.layer` in place of `layerCryptoWeb` or `layerWebCrypto`, supply HTTP separately, and provide an Effect Kdf Layer to `Testing.services()`.
