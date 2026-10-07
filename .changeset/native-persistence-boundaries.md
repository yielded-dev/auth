---
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Use shared native SQL workflows through mapped tables or `NativeSqlTables`. BEHAVIOR CHANGE: update custom adapters to the current `/Adapter` exports and replace removed query-kernel, observation-fence, and legacy transaction helpers.
