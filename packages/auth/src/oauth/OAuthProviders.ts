import { Context, Effect, Layer } from "effect";

import { UnknownOAuthProvider } from "./errors";
import type { OAuthProvider } from "./OAuthProvider";
import type { OAuthProviderKey } from "./schema";

/**
 * The set of configured OAuth providers. Applications construct the complete
 * set in one place, so provider selection is deterministic and duplicate keys
 * fail during layer construction:
 *
 * ```ts
 * const OAuthLive = OAuth.layer.pipe(
 *   Layer.provide(OAuthProviders.layer([
 *     makeGithubOAuthProvider({ clientId, clientSecret }),
 *   ])),
 * )
 * ```
 */
export class OAuthProviders extends Context.Service<
  OAuthProviders,
  {
    readonly lookup: (key: OAuthProviderKey) => Effect.Effect<OAuthProvider, UnknownOAuthProvider>;
  }
>()("effect-auth/OAuthProviders") {
  static readonly layer = (configured: Iterable<OAuthProvider> = []): Layer.Layer<OAuthProviders> =>
    Layer.effect(
      OAuthProviders,
      Effect.gen(function* () {
        const providers = new Map<OAuthProviderKey, OAuthProvider>();

        for (const provider of configured) {
          if (providers.has(provider.key)) {
            return yield* Effect.die(
              new Error(`OAuth provider "${provider.key}" is configured more than once`),
            );
          }
          providers.set(provider.key, provider);
        }

        return OAuthProviders.of({
          lookup: (key) =>
            Effect.suspend(() => {
              const provider = providers.get(key);

              return provider === undefined
                ? Effect.fail(UnknownOAuthProvider.make({ provider: key }))
                : Effect.succeed(provider);
            }),
        });
      }),
    );
}
