---
"@yielded/auth": patch
"@yielded/oauth": patch
"@yielded/jose": patch
---

Add `Microsoft.provider` for Entra ID sign-in, with `oid:tid` subjects and a PKCE supplement for the v2.0 endpoints. Accept `{tenantid}` discovery issuers by substituting the verified `tid` and checking the selected signing key's issuer.
