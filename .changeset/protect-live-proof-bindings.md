---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Protect live proofs from replacement by another request binding and charge issuance budgets only for accepted proofs. BEHAVIOR CHANGE: supply `Proofs.HostIngressLimiter` at construction and `Proofs.ProofRequestContext` per invocation for email proof and password-reset requests; provide raw HTTP operation handlers, codecs, and callback services at `server.handle` invocation.
