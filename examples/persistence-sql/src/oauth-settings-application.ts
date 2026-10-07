import { Hooks, Http, OAuth } from "@yielded/auth";
import { Effect, Layer, type Redacted } from "effect";
import { FetchHttpClient } from "effect/http";

import { CryptoLive } from "../../shared/crypto";
import { SettingsActionsLive, SettingsAuth } from "./oauth-settings-auth";
import { providerLayer } from "./oauth-settings-provider";
import { settingsStorage } from "./oauth-settings-storage";
import { consentLayer } from "./yielded-consent";
import { identityLayer, yielded, YieldedGrantsLive } from "./yielded-identity";
import type { IdentityKeyMaterial } from "./yielded-keys";

export interface SettingsConfiguration {
  readonly origin: URL;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly externalSubject: string;
  readonly displayName: string;
  readonly stylesheet: string;
  readonly agent?: {
    readonly origin: URL;
    readonly secret: Redacted.Redacted<string>;
    readonly keys: typeof IdentityKeyMaterial.Type;
  };
}

/** The host supplies the SQL owner and stable keys; all auth policy is shared. */
export const settingsApplication = (config: SettingsConfiguration) => {
  const secure = config.origin.protocol === "https:";
  const prefix = `${secure ? "__Host-" : ""}oauth-settings-`;

  const http = Http.make(SettingsAuth, {
    origin: config.origin.origin,
    cookie: { prefix, secure },
  });

  const infrastructure = Layer.mergeAll(
    Hooks.LifecycleHooks.empty,
    providerLayer(config),
    OAuth.OAuthReturnTargets.exactRoutes(["/oauth-settings", yielded.paths.authorize]),
    Layer.succeed(SettingsAuth.strategies.oauth.SessionClaims, {
      resolve: () => Effect.succeed({ displayName: config.displayName }),
    }),
  ).pipe(Layer.provideMerge(CryptoLive), Layer.provideMerge(FetchHttpClient.layer));

  const storage = settingsStorage(config.externalSubject).pipe(Layer.provideMerge(infrastructure));

  const live = SettingsAuth.layer.pipe(
    Layer.provide(SettingsActionsLive.pipe(Layer.provideMerge(storage))),
  );

  const agent = config.agent;

  const sharedSignIn =
    agent === undefined
      ? Layer.empty
      : yielded.routes.pipe(
          Layer.provide(
            yielded
              .layer({
                origin: config.origin.origin,
                loginPath: "/sign-in",
                keys: { activeKeyId: "v1", keys: [{ id: "v1", material: agent.keys.consent }] },
                identityKeys: {
                  activeKeyId: "v1",
                  privateKey: agent.keys.privateKey,
                  publicKeys: [agent.keys.publicKey],
                },
                clients: [
                  {
                    clientId: "yielded-agent",
                    name: "Yielded Agent",
                    redirectUris: [`${agent.origin.origin}/travel/auth/yielded/callback`],
                    clientSecret: agent.secret,
                    grantTypes: ["authorization_code"],
                  },
                ],
              })
              .pipe(
                Layer.provide(identityLayer(`${prefix}session`, config.displayName)),
                Layer.provide(YieldedGrantsLive),
                Layer.provide(consentLayer(config.stylesheet, config.displayName)),
                Layer.provide(live),
                Layer.provide(storage),
              ),
          ),
        );

  return Layer.merge(http.routes().pipe(Layer.provide(live)), sharedSignIn).pipe(
    Layer.provide(infrastructure),
  );
};
