---
"@yielded/auth": minor
---

Add opt-in OpenID application scopes, explicit resource audiences, signed JWT access tokens, and rotating refresh grants. Application authorization rechecks scopes and nested JSON claims at code exchange and refresh while preserving the original authentication time.

Expose a resource-server verifier for access tokens using trusted public keys. Existing OpenID defaults keep opaque UserInfo access and disable refresh grants.
