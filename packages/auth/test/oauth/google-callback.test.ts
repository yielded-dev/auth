import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { it } from "@effect/vitest";
import { Auth, Google, Http, OAuth, Operations, Sessions } from "@yielded/auth";
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

const Failure = Schema.Struct({ reason: Schema.String });

// Regression for https://github.com/yielded-dev/auth/issues/289.
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
      Effect.promise(() =>
        handler(
          new Request(`${origin}/auth/google/callback?${new URLSearchParams(query)}`, {
            headers: { cookie: "__Host-effect-auth-request-binding=unbound" },
          }),
        ).then((response) => response.json()),
      ).pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(Failure)),
        Effect.map((failure) => failure.reason),
      );

    const response = { state: "A".repeat(43), code: "code", iss: "https://accounts.google.com" };

    // An unknown, POST-only, or front-channel token parameter is refused before the request binding
    // is read; Google's own parameters pass, and the unbound request fails on its binding instead.
    expect(yield* reason({ ...response, unexpected: "1" })).toBe("request");
    expect(yield* reason({ ...response, user: '{"name":{"firstName":"Ada"}}' })).toBe("request");
    expect(yield* reason({ ...response, id_token: "header.payload.sig" })).toBe("request");
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

// Regression from 9f882813: OAuthCodeResponse.scope was added, but
// http-operation/server.ts omitted `scope` when forwarding callback responses.
it.live("forwards the callback scope parameter to the completion operation", () =>
  Effect.gen(function* () {
    const flows = new Map<string, OAuth.OAuthSignInFlow>();
    const credentials = new Map<string, OAuth.OAuthCredentialSnapshot>();
    let observedScope: string | undefined;

    const journal = {
      prepare: <A>(value: A) => ({
        _tag: "PreparedCommit" as const,
        read: Effect.succeed(value),
      }),
      stage: () => undefined,
    };

    const persistence = Layer.succeed(OAuth.OAuthSignInPersistence, {
      issue: (flow, prepare) =>
        Effect.sync(() => {
          flows.set(flow.context.flowId, flow);

          return prepare({ _tag: "Issued", flow }, journal);
        }),
      consume: (access, prepare) =>
        Effect.sync(() => {
          const flow = flows.get(access.flowId);

          if (flow === undefined || flow.context.responseMode !== access.responseMode)
            return prepare({ _tag: "Rejected" }, journal);
          flows.delete(access.flowId);

          return prepare({ _tag: "Consumed", flow }, journal);
        }),
      resolve: ({ identity }) => Effect.succeed(credentials.get(identity.subject)),
      cleanup: () => Effect.die("unused"),
    });

    const issuer = OAuth.OAuthIssuer.make("https://accounts.google.com");
    const provider = OAuth.OAuthProviderKey.make("google");
    const state = `${"S".repeat(42)}A`;

    const protocol = Layer.succeed(OAuth.OAuthProtocol, {
      prepareAuthorization: () =>
        Effect.succeed({
          configuration: {
            provider,
            protocol: "oidc" as const,
            configurationGeneration: 1,
            issuer,
            responseIssuerMode: "required" as const,
            callbackId: OAuth.OAuthCallbackId.make("google"),
            redirectUri: OAuth.OAuthRedirectUri.make(`${origin}/auth/google/callback`),
          },
          authorizationUrl: Redacted.make("https://accounts.google.com/o/oauth2/v2/auth"),
          secrets: {
            namespace: "effect-auth/oauth-transaction-secrets/v1" as const,
            state: Redacted.make(state),
            oidcNonce: Redacted.make(`${"N".repeat(42)}A`),
          },
        }),
      exchangeVerifiedIdentity: (input) =>
        Effect.sync(() => {
          observedScope = input.response.scope;

          return { identity: { provider, issuer, subject: "google-sub" } };
        }),
    });

    const baseLayer = Layer.mergeAll(
      persistence,
      protocol,
      Layer.mock(Sessions.AuthenticationAuthority)({}),
      Layer.mock(auth.strategies.oauth.SessionClaims)({}),
      OAuth.OAuthReturnTargets.exactRoutes(["/"]),
      OAuth.OAuthTransactionProtector.layer(keyring),
      Auth.RequestBindingConfig.layer({ generation: 1, lifetimeMillis: 600_000, keyring }),
      Layer.succeed(Sessions.SessionSigningKeys, keyring),
    ).pipe(Layer.provideMerge(NodeCrypto.layer));

    const services = yield* Layer.build(baseLayer);
    const app = yield* auth.make.pipe(Effect.provide(services));

    let bindingCredential: Redacted.Redacted<string> | undefined;

    yield* app.signIn({ provider: "google", returnTarget: "/" }).pipe(
      Effect.provideService(Auth.AuthRequest, {
        invocation: Operations.guest,
        credentials: {},
        credentialCommandSink: (commands) =>
          Effect.sync(() => {
            for (const command of commands) {
              if (command._tag === "Issue" && command.slot === "request-binding") {
                bindingCredential = command.credential;
              }
            }
          }),
      }),
    );

    expect(bindingCredential).toBeDefined();

    const { handler, dispose } = HttpRouter.toWebHandler(
      http
        .callbackRoutes()
        .pipe(
          Layer.provide(http.operationLayer),
          Layer.provide(auth.layer),
          Layer.provide(Layer.succeedContext(services)),
        ),
      { disableLogger: true },
    );

    yield* Effect.addFinalizer(() => Effect.promise(dispose));

    const callbackQuery = new URLSearchParams({
      state,
      code: "provider-code",
      iss: "https://accounts.google.com",
      scope: "openid email profile",
    });

    const callbackResponse = yield* Effect.promise(() =>
      handler(
        new Request(`${origin}/auth/google/callback?${callbackQuery}`, {
          headers: {
            cookie: `__Host-effect-auth-request-binding=${Redacted.value(bindingCredential!)}`,
          },
        }),
      ),
    );

    const body = yield* Effect.promise(() => callbackResponse.text());

    expect(observedScope, `status=${callbackResponse.status} body=${body}`).toBe(
      "openid email profile",
    );
  }).pipe(Effect.scoped),
);
