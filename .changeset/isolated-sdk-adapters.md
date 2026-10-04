---
"@yielded/auth": minor
"@yielded/auth-simplewebauthn": minor
---

Move SimpleWebAuthn into its optional companion package. BEHAVIOR CHANGE: import browser and server helpers from `@yielded/auth-simplewebauthn/Browser` or `/Server` and supply the corresponding Layers.
