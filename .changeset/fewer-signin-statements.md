---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
---

Reduce a complete password sign-in to 21 database calls on PostgreSQL and 20 on SQLite by removing a repeated authority read, a separate credential lock, and, without row locks, a repeated attempt read.
