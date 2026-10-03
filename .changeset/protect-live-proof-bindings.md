---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Protect live proofs from another request binding, charge only accepted issuance, and expose `Adapter.makeStorageMappings` for explicit adapter composition. BEHAVIOR CHANGE: supply `Proofs.HostIngressLimiter` at construction and `Proofs.ProofRequestContext` per invocation for email proof and password-reset requests; provide raw HTTP operation handlers, codecs, and callback services at `server.handle` invocation.
