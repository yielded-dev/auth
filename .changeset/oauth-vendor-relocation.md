---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Move plain-OAuth profile fetching, JSON token request bodies, and comma-delimited scope serialization out of `@yielded/oauth` into `@yielded/auth` provider helpers.

BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers can no longer pass `profile`, `tokenBodyFormat`, or `scopeSeparator` to `OAuth.make` or call `client.fetchProfile`; `@yielded/oauth` now handles only standard form-encoded token requests and space-separated scopes. `@yielded/auth` provider behavior and wire format are unchanged across authorization, token exchange, refresh, and profile requests.
