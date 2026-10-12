---
"@yielded/auth": patch
"@yielded/crypto": patch
---

Reject OAuth protector construction with an actionable configuration error when AEAD lacks XChaCha20-Poly1305 support, and document Portable crypto for Workers OAuth without Argon2 Wasm.

BEHAVIOR CHANGE: Implement `supports(algorithm)` on custom `Aead` services.
