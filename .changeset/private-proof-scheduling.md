---
"@yielded/auth": patch
---

Require a host-owned `Proofs.ProofDispatchScheduler` so proof requests can return without waiting for email or SMS provider acceptance. BEHAVIOR CHANGE: provide a bounded scheduler for public requests and use prepared receipts' `schedule` continuation; `layerInline` is an explicit trusted-workflow fallback that exposes provider latency.
