import { Context, DateTime, Effect, Layer, Schema, Semaphore } from "effect";

import { AuthStoreBackend } from "../AuthStore";
import { AuthStoreError } from "../Errors";
import type { TokenDigest } from "../Schema";
import { InvalidOAuthState } from "./errors";
import { OAuthState } from "./schema";

class StoredOAuthState extends Schema.Class<StoredOAuthState>("effect-auth/StoredOAuthState")({
  state: OAuthState,
  consumed: Schema.Boolean,
}) {}

// oxlint-disable-next-line no-restricted-properties -- AuthStoreBackend intentionally returns unknown persisted values.
const decodeStateRow = Schema.decodeUnknownEffect(StoredOAuthState);
const encodeStateRow = Schema.encodeEffect(StoredOAuthState);

const stateKey = (stateDigest: string) => `oauth-state:${stateDigest}`;

const readFailed = AuthStoreError.make({ message: "Auth store read failed" });
const writeFailed = AuthStoreError.make({ message: "Auth store write failed" });

const makeBackendOAuthStateStore = Effect.gen(function* () {
  const backend = yield* AuthStoreBackend;
  const semaphore = yield* Semaphore.make(1);
  const serialized = semaphore.withPermits(1);

  const issue = Effect.fn("OAuthStateStore.issue")(
    function* (state: OAuthState) {
      const row = yield* encodeStateRow(StoredOAuthState.make({ state, consumed: false }));

      yield* backend.put(stateKey(state.stateDigest), row);
    },
    Effect.mapError(() => writeFailed),
  );

  const consume = Effect.fn("OAuthStateStore.consume")(function* (stateDigest: TokenDigest) {
    const now = DateTime.toEpochMillis(yield* DateTime.now);
    const value = yield* backend.get(stateKey(stateDigest)).pipe(Effect.mapError(() => readFailed));

    if (value === undefined) {
      return yield* InvalidOAuthState.make();
    }

    const row = yield* decodeStateRow(value).pipe(
      Effect.mapError(() => AuthStoreError.make({ message: "Corrupt auth store row" })),
    );

    if (row.consumed || now >= DateTime.toEpochMillis(row.state.expiresAt)) {
      return yield* InvalidOAuthState.make();
    }

    // The consumed tombstone (rather than a delete) is what makes replays of a
    // captured callback URL fail deterministically until the row expires out.
    const consumedRow = yield* encodeStateRow(
      StoredOAuthState.make({ ...row, consumed: true }),
    ).pipe(Effect.mapError(() => writeFailed));

    yield* backend.put(stateKey(stateDigest), consumedRow).pipe(Effect.mapError(() => writeFailed));

    return row.state;
  });

  return {
    issue: (state: OAuthState) => serialized(issue(state)),
    consume: (stateDigest: TokenDigest) => serialized(consume(stateDigest)),
  };
});

/**
 * Single-use persistence for pending authorization states. `consume` must be
 * atomic: exactly one of concurrent consumptions of the same state may
 * succeed, and every failure mode (unknown, expired, already consumed)
 * collapses to `InvalidOAuthState`.
 *
 * Adapters implement the interface directly against a store with real
 * transactions, or provide an `AuthStoreBackend` to `layerBackend` — the same
 * backend the challenge/registration `AuthStore` uses; key namespaces are
 * disjoint, so one backend can serve both.
 */
export class OAuthStateStore extends Context.Service<
  OAuthStateStore,
  {
    readonly issue: (state: OAuthState) => Effect.Effect<void, AuthStoreError>;
    /**
     * Checks existence, expiry, and prior consumption as one atomic
     * operation, then marks the state consumed.
     */
    readonly consume: (
      stateDigest: TokenDigest,
    ) => Effect.Effect<OAuthState, InvalidOAuthState | AuthStoreError>;
  }
>()("effect-auth/OAuthStateStore") {
  /** The canonical state machine over whichever `AuthStoreBackend` is provided. */
  static readonly layerBackend: Layer.Layer<OAuthStateStore, never, AuthStoreBackend> =
    Layer.effect(OAuthStateStore)(makeBackendOAuthStateStore);

  /** In-memory adapter for tests and local development; never durable. */
  static readonly layerMemory: Layer.Layer<OAuthStateStore> = OAuthStateStore.layerBackend.pipe(
    Layer.provide(AuthStoreBackend.layerMemory),
  );
}
