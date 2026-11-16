---
"@yielded/auth": patch
---

Issue refresh tokens only when the client's grant policy permits them.

BEHAVIOR CHANGE: Clients declaring `grantTypes` without `refresh_token` receive only an access token. Static and stored clients of `OAuthServer.make` that omit `grantTypes` retain refresh support.
