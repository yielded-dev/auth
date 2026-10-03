# @yielded/auth-persistence-convex

Convex persistence for Yielded Auth passwords, proof challenges, sessions, and
OAuth authorization-server grants. Auth runs in an action; internal functions
validate observed records and publish conditional writes atomically. Preparation
happens before commit, and credentials and hooks are released after acknowledgment.

Use `managed(auth, { requirements })` for default profile provisioning, claims,
and persistence composition. Supply custom services through Effect Layers;
explicit services take precedence over managed defaults. Applications own factor
policy, delivery, retention, and any custom account model. Account provisioning and auth records share the adapter's document
transaction. Effect Schema owns persisted values. Unknown commit outcomes remain
unavailable without automatic retry.

See the [Convex persistence guide](../../docs/src/content/docs/guide/convex.mdx)
and [account composition](../../examples/auth/src/convex-account.ts).
