---
"@yielded/auth": patch
---

Resolve `@yielded/auth` OpenID Connect discovery lazily on first use with zero network I/O during Layer construction, and expose `OAuthProtocol.ready` and `OAuthConnectedProtocol.ready` for opt-in startup warm-up.

BEHAVIOR CHANGE: OIDC metadata checks (issuer matching, advertised authentication methods, PKCE, ID-token algorithms, verifier key setup, and `responseIssuerMode: "discovered"`) now run on first use — including the first callback, token refresh, or revocation after a restart — and fail with `OAuthUnavailable` without consuming pending flows, settling active grants, or claiming revocation jobs. Misconfigured OIDC providers no longer fail Layer construction and report `OAuthUnavailable` until corrected. Run `(yield* OAuthProtocol).ready?.()` (and `(yield* OAuthConnectedProtocol).ready?.()` when using connected grants) during startup if you require fail-fast boot validation.
