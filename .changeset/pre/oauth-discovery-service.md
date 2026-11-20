---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Add the `Discovery` service (`Metadata`, `makeLocal`/`layerLocal`, and lazy, scoped `makeRemote`/`layerRemote`) to `@yielded/oauth`, remove `Oidc.discover` and `Oidc.discoveredIssuerMatches`, and move discovery-time Microsoft Entra `{tenantid}` / `consumers` matching into `@yielded/auth`.

BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers must replace `Oidc.discover` with `Discovery.makeRemote` or `Discovery.layerRemote` (and supply an explicit `issuerMatcher` for non-exact issuers such as Microsoft Entra `{tenantid}` templates). `@yielded/auth` OIDC and Entra discovery behavior is unchanged.
