---
"@yielded/auth-persistence-convex": minor
"@yielded/auth": patch
---

Add managed Convex persistence for password accounts, proof-backed recovery, sessions, and OAuth grants with replaceable Effect services. Define session issuance time as authority time sampled during preparation while retaining fresh expiry checks at the conditional commit.
