import * as OAuthServer from "@yielded/auth/OAuthServer";
import type { Layer } from "effect";
import { Effect, Redacted } from "effect";
import { expectTypeOf } from "vite-plus/test";

// Compile-only contract for literal scope inference. Runtime proofs
// cannot detect a typo accepted by the TypeScript API.
export const literalScopes = () => {
  const applicationScopes = ["documents:read", "documents:write"] as const;

  const resource = OAuthServer.make("typed-resource", {
    scopes: ["documents:read", "documents:write"],
  });

  const identity = OAuthServer.makeOpenId("typed-identity", {
    scopes: applicationScopes,
  });

  const defaults = OAuthServer.makeOpenId("typed-defaults");

  expectTypeOf<typeof resource.Scope.Type>().toEqualTypeOf<"documents:read" | "documents:write">();
  expectTypeOf<typeof identity.Scope.Type>().toEqualTypeOf<
    "openid" | "profile" | "email" | "documents:read" | "documents:write"
  >();
  expectTypeOf<typeof defaults.Scope.Type>().toEqualTypeOf<"openid" | "profile" | "email">();
  expectTypeOf<(typeof identity.Access.Type.scopes)[number]>().toEqualTypeOf<
    "openid" | "profile" | "email" | "documents:read" | "documents:write"
  >();

  resource.middleware(["documents:read"]);
  identity.middleware(["openid", "documents:read"]);
  // @ts-expect-error The resource did not declare this scope.
  resource.middleware(["documents:raed"]);
  // @ts-expect-error OpenID adds its standard scopes, not arbitrary strings.
  identity.middleware(["documents:raed"]);
  // @ts-expect-error The default OpenID server has no application scopes.
  defaults.middleware(["documents:read"]);

  identity.Authorization.of({
    // @ts-expect-error Authorization cannot grant an undeclared scope.
    authorize: () => Effect.succeed({ scopes: ["documents:raed"] }),
  });

  identity.Identity.of({
    current: Effect.succeed(undefined),
    active: () => Effect.succeed(true),
    profile: ({ scopes }) => {
      expectTypeOf(scopes[0]).toEqualTypeOf<
        "openid" | "profile" | "email" | "documents:read" | "documents:write"
      >();

      return Effect.succeed({});
    },
  });

  identity.Authorization.of({
    authorize: ({ scopes }) => {
      expectTypeOf(scopes[0]).toEqualTypeOf<
        "openid" | "profile" | "email" | "documents:read" | "documents:write"
      >();

      return Effect.succeed({ scopes });
    },
  });

  return Effect.gen(function* () {
    const resourceService = yield* resource.Service;
    const access = yield* resourceService.verify(Redacted.make("credential"));

    expectTypeOf(access.scopes[0]).toEqualTypeOf<"documents:read" | "documents:write">();

    const identityService = yield* identity.Service;
    const identityAccess = yield* identityService.verify(Redacted.make("credential"));

    expectTypeOf(identityAccess.scopes[0]).toEqualTypeOf<
      "openid" | "profile" | "email" | "documents:read" | "documents:write"
    >();
    const current = yield* identity.CurrentAccess;

    if (current !== undefined)
      expectTypeOf(current.scopes[0]).toEqualTypeOf<
        "openid" | "profile" | "email" | "documents:read" | "documents:write"
      >();

    const configured = yield* OAuthServer.makeAccessTokenVerifier({
      issuer: "https://identity.example.com",
      resource: "https://resource.example.com",
      publicKeys: [],
      scopes: ["documents:read", "openid"],
    });

    const configuredAccess = yield* configured.verify(Redacted.make("credential"));

    expectTypeOf(configuredAccess.scopes[0]).toEqualTypeOf<"documents:read" | "openid">();

    const unconfigured = yield* OAuthServer.makeAccessTokenVerifier({
      issuer: "https://identity.example.com",
      resource: "https://resource.example.com",
      publicKeys: [],
    });

    const unconfiguredAccess = yield* unconfigured.verify(Redacted.make("credential"));

    expectTypeOf(unconfiguredAccess.scopes[0]).toEqualTypeOf<string>();
  });
};

export const serviceScopes = () => {
  const narrow = OAuthServer.makeOpenId("same-id", { scopes: ["read"] });
  const broad = OAuthServer.makeOpenId("same-id", { scopes: ["read", "write"] });

  return (layers: {
    readonly server: Layer.Layer<typeof broad.Service.Identifier>;
    readonly authorization: Layer.Layer<typeof broad.Authorization.Identifier>;
    readonly identity: Layer.Layer<typeof broad.Identity.Identifier>;
  }) => {
    const server = Effect.provide(narrow.Service, layers.server);
    const authorization = Effect.provide(narrow.Authorization, layers.authorization);
    const identity = Effect.provide(narrow.Identity, layers.identity);

    expectTypeOf<Effect.Services<typeof server>>().toEqualTypeOf<
      typeof narrow.Service.Identifier
    >();
    expectTypeOf<Effect.Services<typeof authorization>>().toEqualTypeOf<
      typeof narrow.Authorization.Identifier
    >();
    expectTypeOf<Effect.Services<typeof identity>>().toEqualTypeOf<
      typeof narrow.Identity.Identifier
    >();
  };
};
