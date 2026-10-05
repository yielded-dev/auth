---
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Reduce PostgreSQL persistence acquisition latency while continuing to reject missing columns and unique keys. Avoid repeated passkey initialization writes when current policy and admission ownership already match.
