import { it as effectIt } from "@effect/vitest";
import { Effect } from "effect";
import { describe } from "vite-plus/test";

import { OAuthStateStore } from "../../src/oauth/OAuthStateStore";
import { oauthStateStoreConformanceCases } from "../../src/testing/conformance/OAuthStateStore";

// The store contract every OAuthStateStore adapter must satisfy, run against
// the bundled memory adapter. Downstream adapters run the same exported
// suite.

describe("OAuthStateStore conformance (memory)", () => {
  for (const conformance of oauthStateStoreConformanceCases) {
    effectIt.effect(conformance.name, () =>
      conformance.run.pipe(Effect.provide(OAuthStateStore.layerMemory)),
    );
  }
});
