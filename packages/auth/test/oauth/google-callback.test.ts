import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { it } from "@effect/vitest";
import { Auth, Google, Http, OAuth, Sessions } from "@yielded/auth";
import { AuthContract } from "@yielded/auth/contracts";
import * as Effect from "effect/Effect";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as HttpRouter from "effect/http/HttpRouter";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import { expect } from "vite-plus/test";

const origin = "https://app.example.com";

const keyring = {
  activeKeyId: "test",
  keys: [{ id: "test", material: Redacted.make("A".repeat(43)) }],
};

const contract = AuthContract.make("test/google-callback", {
  claims: Schema.Struct({}),
  actions: (sessions) => ({
    signIn: AuthContract.oauthSignIn(),
    completeSignIn: AuthContract.oauthCompleteSignIn(sessions),
  }),
});

const auth = Auth.make(contract, {
  sessions: Sessions.stateless(),
  strategies: { oauth: OAuth.make({ profiles: { google: Google.GoogleUserProfile } }) },
  defaultStrategy: "oauth",
});

const http = Http.make(auth, {
  origin,
  oauth: {
    providers: {
      google: Google.provider({ clientId: "client", clientSecret: Redacted.make("secret") }),
    },
  },
});

const discovery = HttpClient.make((request, url) =>
  Effect.succeed(
    HttpClientResponse.fromWeb(
      request,
      url.href === "https://accounts.google.com/.well-known/openid-configuration"
        ? Response.json({
            issuer: "https://accounts.google.com",
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint: "https://oauth2.googleapis.com/token",
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"],
            code_challenge_methods_supported: ["S256"],
            token_endpoint_auth_methods_supported: ["client_secret_post"],
            authorization_response_iss_parameter_supported: true,
          })
        : new Response(null, { status: 404 }),
    ),
  ),
);

it.effect("admits the parameters Google appends to its callback", () =>
  Effect.gen(function* () {
    const { handler, dispose } = HttpRouter.toWebHandler(
      http.callbackRoutes().pipe(
        Layer.provide(http.operationLayer),
        Layer.provide(http.layer),
        Layer.provide(Layer.succeed(HttpClient.HttpClient, discovery)),
        // The callback refuses or admits its parameters before any of these is used.
        Layer.provide(Layer.mock(Sessions.AuthenticationAuthority)({})),
        Layer.provide(Layer.mock(OAuth.OAuthSignInPersistence)({})),
        Layer.provide(Layer.mock(auth.strategies.oauth.SessionClaims)({})),
        Layer.provide(OAuth.OAuthReturnTargets.exactRoutes(["/"])),
        Layer.provide(OAuth.OAuthTransactionProtector.layer(keyring)),
        Layer.provide(
          Auth.RequestBindingConfig.layer({ generation: 1, lifetimeMillis: 600_000, keyring }),
        ),
        Layer.provide(Layer.succeed(Sessions.SessionSigningKeys, keyring)),
        Layer.provide(NodeCrypto.layer),
      ),
      { disableLogger: true },
    );

    yield* Effect.addFinalizer(() => Effect.promise(dispose));

    const reason = (query: Record<string, string>) =>
      Effect.promise(async () => {
        const response = await handler(
          new Request(`${origin}/auth/google/callback?${new URLSearchParams(query)}`, {
            headers: { cookie: "__Host-effect-auth-request-binding=unbound" },
          }),
        );

        return ((await response.json()) as { readonly reason?: string }).reason;
      });

    const response = { state: "A".repeat(43), code: "code", iss: "https://accounts.google.com" };

    // An unknown parameter is refused before the request binding is read; Google's
    // own parameters pass, and the unbound request fails on its binding instead.
    expect(yield* reason({ ...response, unexpected: "1" })).toBe("request");
    expect(
      yield* reason({
        ...response,
        scope: "openid email profile",
        authuser: "0",
        prompt: "consent",
        hd: "example.com",
      }),
    ).toBe("credentials");
  }).pipe(Effect.scoped),
);
