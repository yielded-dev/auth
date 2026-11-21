---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Fix a Microsoft Entra sign-in security issue by rejecting personal Microsoft accounts on `organizations` registrations. Require a matching signing-key issuer when `consumers` discovery returns the concrete issuer.
