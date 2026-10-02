import { KeyValueStore } from "effect/persistence";

import { mountAccountApp } from "../../shared/account/browser";
import { minimumPasswordLength } from "../../shared/account/contract";
import { BrowserLoginBanner } from "./browser-login-banner";
import { makeClient } from "./client";

const client = makeClient(
  { baseUrl: window.location.origin },
  KeyValueStore.layerStorage(() => window.sessionStorage),
);

mountAccountApp(client, {
  number: "03",
  description: "Effect SQL example",
  minimumPasswordLength,
  banner: <BrowserLoginBanner client={client} />,
});
