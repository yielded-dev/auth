import { KeyValueStore } from "effect/unstable/persistence";

import { mountAccountApp } from "../../shared/account/browser";
import { makeClient } from "./client";
import { minimumPasswordLength } from "./contract";

const client = makeClient(
  { baseUrl: window.location.origin },
  KeyValueStore.layerStorage(() => window.sessionStorage),
);

mountAccountApp(client, {
  number: "04",
  description: "Custom services example",
  minimumPasswordLength,
  username: true,
});
