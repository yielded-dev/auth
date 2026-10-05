---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Reduce SQL queries for authentication, credential management, and cleanup across SQL adapters. Keep SQLite cleanup batches within Durable Object statement limits.
