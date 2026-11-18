---
"@yielded/auth": minor
---

Add an optional `Authorization` service to `OAuthServer.make`, so applications can recheck permission and attach `claims` at every code exchange and refresh without the OpenID profile.
