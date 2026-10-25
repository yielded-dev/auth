---
"@yielded/auth": minor
---

Remember a public session snapshot in application-supplied local storage and expose its verification state through `auth.identity`. Gate account-owned workflows with `auth.verifiedSession(expectedSubject)` while preserving remembered local work through offline session failures.

BEHAVIOR CHANGE: Rename custom actions called `identity` or `verifiedSession`; these names are now reserved.
