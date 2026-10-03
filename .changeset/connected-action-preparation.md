---
"@yielded/auth": patch
"@yielded/auth-crypto": patch
"@yielded/auth-persistence-drizzle": patch
---

Prepare connected OAuth flows before verifying independent exact-action evidence, and resolve begin, callback and disconnect targets through private server services. **BEHAVIOR CHANGE:** call `prepareBegin` before `begin`, retain its private `connected-intent` credential and original command inputs, and map credentials through Operation HTTP instead of public JSON.
