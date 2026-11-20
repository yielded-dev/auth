---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Replace `@yielded/oauth/Errors` with `OAuthError` and its closed `reason` union, reshape `Pkce` around `Verifier`, `Challenge`, `Pair`, infallible `generate`, and `challenge`, and raise the `effect` peer dependency floor to `^4.1.4` across the package family.
