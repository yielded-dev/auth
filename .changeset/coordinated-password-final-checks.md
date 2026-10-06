---
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Check a coordinated password mutation's final state again after application work, in interactive transactions and D1 batches. BEHAVIOR CHANGE: a coordinated transaction now accepts one password mutation; a second fails with `PasswordUnavailable`.
