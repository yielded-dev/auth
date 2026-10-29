---
"@yielded/auth": patch
"@yielded/jose": patch
"@yielded/oauth": patch
---

Use Effect crypto for key derivation, HMAC, authenticated encryption, signatures, and key formats, retaining portable Argon2id and scrypt in Auth. BEHAVIOR CHANGE: replace `@yielded/crypto` with Effect crypto Layers and `Password.KdfAdmission.layer()`; use `PasswordScrypt.layer` for scrypt, and opaque Effect keys for JOSE key material.
