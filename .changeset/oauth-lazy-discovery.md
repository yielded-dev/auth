---
"@yielded/auth": patch
---

Switch `@yielded/auth` OpenID Connect providers to lazy discovery through `Discovery.makeRemote` on first use so Layer construction performs zero network I/O and server startup succeeds while an IdP is unavailable.

BEHAVIOR CHANGE: OIDC providers no longer resolve discovery at Layer construction; metadata-dependent checks (issuer matching, advertised authentication methods, PKCE, ID-token algorithms, and `responseIssuerMode: "discovered"`) now run on first flow resolution and surface as `OAuthUnavailable`, caching valid metadata for the Layer scope and enforcing a 30-second cooldown after failures. Static configuration checks (including shared callbacks across issuers) still fail Layer construction with `OpenIdConnectConfigurationError`. Applications that require fail-fast boot-time discovery validation should run `Discovery.resolve` with `Discovery.layerRemote` from `@yielded/oauth/Discovery` at startup.
