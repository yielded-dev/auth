---
"@yielded/crypto": minor
"@yielded/auth": minor
---

Use native scrypt on Node, Bun, and Workers, and select `defaultScryptPasswordHashingConfig` to migrate passwords on successful sign-in. **BEHAVIOR CHANGE:** Custom `Kdf` service implementations must provide `scrypt`.
