---
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Allow composed SQL persistence alongside explicit strategy services, and safely read mapped SQL IDs with differing physical types. Keep passkey, session, and pending-authentication snapshots coherent when their mappings require independently bound reads.
