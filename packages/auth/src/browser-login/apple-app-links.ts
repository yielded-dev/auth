import { Effect, Schema } from "effect";

import {
  AppleAppSiteAssociation,
  type Client,
  Clients,
  ConfigurationError,
  HttpsReturnUrl,
} from "./models";

/** Generate both Apple association services from the same server-owned registry.
 * Host the result over HTTPS without redirects at the selected origin's
 * /.well-known/apple-app-site-association. Apps must separately sign the matching
 * webcredentials (iOS auth sessions) or applinks (macOS Universal Links) entitlement.
 * This builds deployment configuration; it does not verify an installed app. */
export const appleAppSiteAssociation = Effect.fnUntraced(function* (options: {
  readonly clients: ReadonlyArray<Client>;
  readonly origin: string;
}) {
  const clients = yield* Schema.decodeEffect(Clients)(options.clients).pipe(
    Effect.mapError(() => ConfigurationError.make({})),
  );

  const origin = yield* Schema.decodeEffect(
    Schema.String.check(
      Schema.makeFilter((text) => {
        try {
          const url = new URL(text);

          return url.origin === text && Schema.is(HttpsReturnUrl)(url.href);
        } catch {
          return false;
        }
      }),
    ),
  )(options.origin).pipe(Effect.mapError(() => ConfigurationError.make({})));

  const apps = new Map<string, Set<string>>();

  for (const client of clients) {
    if (!("appleAppId" in client)) continue;
    const url = new URL(client.returnUrl);

    if (url.origin !== origin) continue;
    const paths = apps.get(client.appleAppId) ?? new Set<string>();

    paths.add(url.pathname);
    apps.set(client.appleAppId, paths);
  }
  if (apps.size === 0) return yield* ConfigurationError.make({});

  return yield* Schema.decodeEffect(AppleAppSiteAssociation)({
    applinks: {
      details: [...apps].map(([appId, paths]) => ({
        appIDs: [appId],
        components: [...paths].map((path) => ({ "/": path })),
      })),
    },
    webcredentials: { apps: [...apps.keys()] },
  }).pipe(Effect.mapError(() => ConfigurationError.make({})));
});
