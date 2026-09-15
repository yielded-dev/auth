import { DateTime, Duration, Effect, Schema } from "effect";
import { TestClock } from "effect/testing";

import { OAuthStateStore } from "../../oauth/OAuthStateStore";
import { OAuthProviderKey, OAuthState } from "../../oauth/schema";
import { check, decodeSubjectId, expectFailure, tokenDigestOf } from "./support";

// Pure store-contract checks for `OAuthStateStore` adapters: state digests
// are opaque strings to the store, so the suite fabricates them directly.
// Run each case with `it.effect` (TestClock required) against the adapter's
// layer.

export interface OAuthStateStoreConformanceCase {
  readonly name: string;
  readonly run: Effect.Effect<void, never, OAuthStateStore>;
}

const conformanceProvider = Schema.decodeSync(OAuthProviderKey)("conformance");

const makeOAuthState = (options: {
  readonly token: string;
  readonly subject?: string;
  readonly lifetime?: Duration.Duration;
}): Effect.Effect<OAuthState> =>
  Effect.map(DateTime.now, (now) =>
    OAuthState.make({
      stateDigest: tokenDigestOf(options.token),
      provider: conformanceProvider,
      subjectId: decodeSubjectId(options.subject ?? "conformance-subject"),
      redirectUri: "https://app.conformance.test/oauth/callback",
      issuedAt: now,
      expiresAt: DateTime.addDuration(now, options.lifetime ?? Duration.minutes(10)),
    }),
  );

const oauthStateCase = <CaseError>(
  name: string,
  run: Effect.Effect<void, CaseError, OAuthStateStore>,
): OAuthStateStoreConformanceCase => ({ name, run: Effect.orDie(run) });

export const oauthStateStoreConformanceCases: ReadonlyArray<OAuthStateStoreConformanceCase> = [
  oauthStateCase(
    "consume returns the issued state exactly once",
    Effect.gen(function* () {
      const store = yield* OAuthStateStore;

      yield* store.issue(yield* makeOAuthState({ token: "oauth-once" }));
      const state = yield* store.consume(tokenDigestOf("oauth-once"));

      yield* check(
        state.redirectUri === "https://app.conformance.test/oauth/callback",
        "consume must return the stored state",
      );
      yield* expectFailure(
        store.consume(tokenDigestOf("oauth-once")),
        "InvalidOAuthState",
        "a consumed state must reject replays",
      );
    }),
  ),

  oauthStateCase(
    "parallel consumption produces exactly one success",
    Effect.gen(function* () {
      const store = yield* OAuthStateStore;

      yield* store.issue(yield* makeOAuthState({ token: "oauth-parallel" }));

      const exits = yield* Effect.all(
        Array.from({ length: 8 }, () =>
          Effect.exit(store.consume(tokenDigestOf("oauth-parallel"))),
        ),
        { concurrency: "unbounded" },
      );

      const successes = exits.filter((exit) => exit._tag === "Success").length;

      yield* check(successes === 1, `expected exactly one success, saw ${successes}`);
    }),
  ),

  oauthStateCase(
    "an expired state is rejected at its expiry instant",
    Effect.gen(function* () {
      const store = yield* OAuthStateStore;

      yield* store.issue(yield* makeOAuthState({ token: "oauth-expiry" }));
      yield* TestClock.adjust(Duration.minutes(10));
      yield* expectFailure(
        store.consume(tokenDigestOf("oauth-expiry")),
        "InvalidOAuthState",
        "a state must be rejected once its expiry instant is reached",
      );
    }),
  ),

  oauthStateCase(
    "unknown digests fail with the generic typed error",
    expectFailure(
      Effect.flatMap(OAuthStateStore, (store) => store.consume(tokenDigestOf("oauth-unknown"))),
      "InvalidOAuthState",
      "an unknown state digest must map to the generic state error",
    ),
  ),
];
