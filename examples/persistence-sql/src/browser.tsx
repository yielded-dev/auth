import { KeyValueStore } from "effect/persistence";

import { mountAccountApp } from "../../shared/account/browser";
import { minimumPasswordLength } from "../../shared/account/contract";
import { BrowserLoginBanner, returningToApp, withBrowserLogin } from "./browser-login-banner";
import { makeClient } from "./client";

const login = withBrowserLogin(
  makeClient(
    { baseUrl: window.location.origin },
    KeyValueStore.layerStorage(() => window.sessionStorage),
  ),
);

mountAccountApp(login.client, {
  number: "03",
  description: "Effect SQL example",
  minimumPasswordLength,
  banner: <BrowserLoginBanner login={login} />,
  returnToApp: returningToApp,
});
