---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
---

Reduce SQL round trips during passkey enrollment and authentication while preserving authorization, expiry, row locks and atomic credential writes. Reduce redundant validation reads after inserts across SQL authentication persistence.
