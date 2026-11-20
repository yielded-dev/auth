---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Replace `@yielded/oauth/Errors` with `OAuthError` and its closed `reason` union, reshape `Pkce` around `Verifier`, `Challenge`, `Pair`, infallible `generate`, and `challenge`, and raise the `effect` peer dependency floor to `^4.1.4` across the package family.

BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers must migrate from `@yielded/oauth/Errors` (`ConfigurationError`, `Rejected`, `Unavailable`) to `@yielded/oauth/OAuthError` (matching on `error.reason._tag`) and from `Pkce.make()` / `Pkce.random()` to `Pkce.generate` / `Pkce.challenge`. All packages in the family now require `effect@^4.1.4`.
