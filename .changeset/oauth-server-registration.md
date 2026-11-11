---
"@yielded/auth": minor
---

Add opt-in RFC 7591 dynamic registration of public clients to `OAuthServer.make`, with the `registration` option and the `Registration` service. Add `scopes` to `Client` to limit a client to those scopes.

BEHAVIOR CHANGE: `OAuthServer.make` no longer issues a refresh token to a client whose `grantTypes` omits `refresh_token`.
