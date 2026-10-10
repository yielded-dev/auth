---
"@yielded/auth": patch
"@yielded/oauth": patch
"@yielded/jose": patch
"@yielded/crypto": patch
---

Add `Apple.provider` for Sign in with Apple. form_post callbacks mint an ES256 client-secret JWT from a `.p8` key, and the public callback route accepts that POST with a `SameSite=None; Secure` request-binding cookie.

BEHAVIOR CHANGE: Custom `Signature` services must implement `decodePrivateKey`.
