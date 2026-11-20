---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Resolve `@yielded/auth` OpenID Connect discovery lazily on first use with zero network I/O during Layer construction, expose `OAuthProtocol.ready` and `OAuthConnectedProtocol.ready` for opt-in startup warm-up, and measure `Discovery.makeRemote` failure cooldown from completion time.

BEHAVIOR CHANGE: OIDC metadata checks (issuer matching, advertised authentication methods, PKCE, ID-token algorithms, verifier key setup, and `responseIssuerMode: "discovered"`) now run on first use — including the first callback, token refresh, or revocation after a restart — and fail with `OAuthUnavailable` without consuming pending flows, settling active grants, or claiming revocation jobs. Metadata-dependent OIDC configuration failures no longer fail Layer construction (static configuration errors still fail at build time) and report `OAuthUnavailable` until corrected. During revocation maintenance, each pass checks readiness for every installed connected registration before claiming, so one IdP outage delays all revocations in that installation until recovery rather than settling jobs to `Unknown`. Run `yield* ((yield* OAuthProtocol).ready?.() ?? Effect.void)` (and `yield* ((yield* OAuthConnectedProtocol).ready?.() ?? Effect.void)` when using connected grants) during startup if you require fail-fast boot validation.
