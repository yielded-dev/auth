import { it as effectIt } from "@effect/vitest";
import { Effect } from "effect";
import { describe } from "vite-plus/test";

import { OAuthConnectionStore } from "../../src/oauth/OAuthConnectionStore";
import { oauthConnectionStoreConformanceCases } from "../../src/testing/conformance/OAuthConnectionStore";

// The store contract every OAuthConnectionStore adapter must satisfy, run
// against the bundled memory adapter. A production (encrypting) adapter runs
// the same exported suite as its acceptance test.

describe("OAuthConnectionStore conformance (memory)", () => {
  for (const conformance of oauthConnectionStoreConformanceCases) {
    effectIt.effect(conformance.name, () =>
      conformance.run.pipe(Effect.provide(OAuthConnectionStore.layerMemory)),
    );
  }
});
