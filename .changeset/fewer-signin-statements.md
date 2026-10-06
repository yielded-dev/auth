---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
---

Reduce a complete password sign-in to 20 database calls on PostgreSQL and SQLite by removing a repeated authority read, a repeated attempt read, and a separate credential lock.
