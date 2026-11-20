---
"@yielded/auth": patch
---

Parameterize `OAuthServer` over an optional string-encoded `subject` schema, `cookiePrefix`, and `onFailure` reporter across `make`, `makeOpenId`, and access-token verifiers. Preserve `SubjectId`, `yielded-` consent cookies, and Yielded Auth diagnostics as defaults.
