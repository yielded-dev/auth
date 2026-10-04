---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Remove unnecessary OIDC signing service requirements from GitHub provider setup. Keep direct GitHub, Strava, and OIDC imports limited to the protocol and token handling modules they use.
