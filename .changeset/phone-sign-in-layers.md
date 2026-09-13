---
"@yielded/auth": minor
---

Separate phone sign-in from optional registration and number-management strategies, and acquire phone admission through the strategy Layer while keeping request context per call. Supply default crypto and hooks in `phonePersistenceLayer`.

BEHAVIOR CHANGE: `PhoneOtp.make` and `PhoneOtp.makeModule` expose sign-in only. Select `PhoneOtp.makeLifecycle` for lifecycle operations and move its `lifecycle` configuration there; share the original namespace with sign-in to preserve credentials, proofs, and the claims service. SMS delivery remains an explicit Layer dependency.
