import { Context, type Effect } from "effect";
import type { KeyValueStoreError } from "effect/persistence/KeyValueStore";

/** Atomic writes to the SAME keys and values exposed by the root KeyValueStore.
 * All authority writers must use this capability; plain KV modify is not atomic.
 * Check expiresAtMillis against the authority's clock atomically with the write.
 * Return false for a version mismatch or an expired deadline. Never retry an
 * unknown write outcome. */
export class AtomicKeyValueStore extends Context.Service<
  AtomicKeyValueStore,
  {
    readonly consistency: "strong" | "eventual";
    readonly compareAndSet: (
      key: string,
      expected: string | undefined,
      value: string,
      options?: { readonly expiresAtMillis?: number },
    ) => Effect.Effect<boolean, KeyValueStoreError>;
  }
>()("effect-auth/key-value/AtomicKeyValueStore") {}
