import { it } from "@effect/vitest";
import * as Auth from "@yielded/auth/Auth";
import * as AuthContract from "@yielded/auth/AuthContract";
import * as GitHub from "@yielded/auth/GitHub";
import * as AuthHttp from "@yielded/auth/Http";
import type { OAuthSignInBegin } from "@yielded/auth/OAuth";
import { OAuthProtocol, OAuthRejected, OAuthReturnTarget } from "@yielded/auth/OAuth";
import {
  AuthCredentialCommandCollector,
  guest,
  makeRequestBinding,
} from "@yielded/auth/Operations";
import { SessionInvalid } from "@yielded/auth/Sessions";
import { Context, DateTime, Effect, Encoding, Layer, Redacted, Schema } from "effect";
import { HttpRouter, HttpServer } from "effect/unstable/http";
import { expect, expectTypeOf } from "vite-plus/test";

import { cryptoLayer } from "../../src/auth/defaults";
import { makeOAuthMethod } from "../../src/oauth/signInModule";
import { makeSessionModule } from "../../src/sessions/module";

const contract = AuthContract.make("test/callback", {
  claims: Schema.Struct({}),
  actions: (sessions) => ({
    start: AuthContract.oauthSignIn(),
    finish: AuthContract.oauthCompleteSignIn(sessions),
  }),
});

const Begin = contract.actions.start.route.operation.rpc.payloadSchema;
const Complete = contract.actions.finish.route.operation.rpc.payloadSchema;
const binding = makeRequestBinding("test/callback", "oauth-entry");

const method = makeOAuthMethod("test/callback", {
  sessions: makeSessionModule("test/callback/sessions", contract.claims),
});

const bindingConfig = Auth.RequestBindingConfig.layer({
  generation: 1,
  lifetimeMillis: 60_000,
  keyring: {
    activeKeyId: "test",
    keys: [
      { id: "test", material: Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32).fill(7))) },
    ],
  },
});

class CallbackRenderer extends Context.Service<
  CallbackRenderer,
  { readonly render: Effect.Effect<Response> }
>()("test/callback/Renderer") {}

// The substitute owns issuance/completion at the operation seam. The real
// public starter allocates IDs; signed binding and provider declarations
// exercise callback correlation. Protocol exchange has its own adapter suite.
const makeApp = (custom: boolean) => {
  const completed: Array<typeof Complete.Type> = [];
  const begun: Array<typeof OAuthSignInBegin.Type> = [];

  type Api = Auth.SessionApi<typeof contract.sessions.Session.Type> & {
    readonly start: (
      input: unknown,
    ) => Effect.Effect<
      typeof contract.actions.start.route.operation.rpc.successSchema.Type,
      OAuthRejected,
      Auth.AuthRequest
    >;
    readonly finish: (
      input: unknown,
    ) => Effect.Effect<
      typeof contract.actions.finish.route.operation.rpc.successSchema.Type,
      OAuthRejected,
      Auth.AuthRequest
    >;
  };

  class AppAuth extends Context.Service<AppAuth, Api>()("test/callback/Auth") {
    static readonly contract = contract;
    static readonly sessions = contract.sessions;
    static readonly layer = Layer.effect(
      this,
      Effect.gen(function* () {
        const protocol = yield* OAuthProtocol;
        const binder = yield* binding.RequestBinding;

        const beginHandler = method.operations.Begin.credentialHandlerLayer(
          Effect.fn(function* (input) {
            begun.push(input);

            const issued = yield* binder
              .issue(input.flowId)
              .pipe(Effect.mapError(() => OAuthRejected.make({})));

            const prepared = yield* protocol.prepareAuthorization(input);

            return {
              value: { ...issued.value, authorizationUrl: prepared.authorizationUrl },
              credentialCommands: issued.credentialCommands,
            };
          }),
        );

        return AppAuth.of({
          verifySession: () => SessionInvalid.make({}),
          getSession: () => Effect.succeed(null),
          requireSession: () => SessionInvalid.make({}),
          renewSession: () => SessionInvalid.make({}),
          signOut: () => Effect.die("unused session method"),
          start: Effect.fn(
            function* (raw) {
              const input = yield* Schema.decodeUnknownEffect(Begin)(raw);
              const request = yield* Auth.AuthRequest;

              return yield* method
                .signIn(request.invocation, input)
                .pipe(
                  Effect.provide([beginHandler, cryptoLayer]),
                  Effect.provideService(
                    AuthCredentialCommandCollector,
                    request.credentialCommandSink,
                  ),
                );
            },
            Effect.mapError(() => OAuthRejected.make({})),
          ),
          finish: Effect.fn(
            function* (raw) {
              const input = yield* Schema.decodeUnknownEffect(Complete)(raw);
              const request = yield* Auth.AuthRequest;
              const credential = request.credentials["request-binding"];

              if (credential === undefined) return yield* OAuthRejected.make({});
              yield* binder.verify(input.flowId, credential);
              completed.push(input);
              yield* request.credentialCommandSink([
                {
                  _tag: "Issue",
                  slot: "session",
                  credential: Redacted.make("private-session"),
                  expiresAtMillis: DateTime.toEpochMillis(yield* DateTime.now) + 60_000,
                },
                { _tag: "Clear", slot: "request-binding" },
              ]);

              return {
                _tag: "Cancelled" as const,
                returnTarget: OAuthReturnTarget.make("/account"),
              };
            },
            Effect.mapError(() => OAuthRejected.make({})),
          ),
        });
      }),
    ).pipe(Layer.provide(binding.layer), Layer.provide(cryptoLayer));
  }

  const options = {
    origin: "https://app.test",
    oauth: {
      providers: {
        github: GitHub.provider({ clientId: "test", clientSecret: Redacted.make("secret") }),
      },
      ...(custom
        ? {
            callbacks: {
              github: {
                path: "/custom/github" as const,
                callbackId: "custom-github",
                respond: () => Effect.flatMap(CallbackRenderer, (renderer) => renderer.render),
              },
            },
          }
        : {}),
    },
  };

  const http = AuthHttp.make(AppAuth, options);
  const callbackRoutes = AuthHttp.layer(AppAuth, options);

  expectTypeOf<
    CallbackRenderer extends Layer.Services<typeof callbackRoutes> ? true : false
  >().toEqualTypeOf<true>();
  expectTypeOf<
    Extract<Layer.Services<typeof callbackRoutes>, AppAuth | OAuthProtocol>
  >().toEqualTypeOf<never>();

  const routes = callbackRoutes.pipe(
    Layer.provide(bindingConfig),
    Layer.provide(HttpServer.layerServices),
    Layer.provide(
      Layer.succeed(CallbackRenderer, {
        render: Effect.succeed(
          new Response("Continue registration", { headers: { "cache-control": "public" } }),
        ),
      }),
    ),
  );

  const localSignIn = Effect.gen(function* () {
    const auth = yield* AppAuth;

    return yield* auth.start({ provider: "github", returnTarget: "/account" });
  }).pipe(
    Effect.provide(http.layer.pipe(Layer.provide(bindingConfig))),
    Effect.provideService(Auth.AuthRequest, {
      invocation: guest,
      credentials: {},
      credentialCommandSink: () => Effect.void,
    }),
  );

  return { http, routes, completed, begun, localSignIn };
};

it.effect(
  "mounts the advertised callback and recovers its flow only from the verified private cookie",
  () =>
    Effect.gen(function* () {
      for (const custom of [false, true]) {
        const app = makeApp(custom);

        const web = yield* Effect.acquireRelease(
          Effect.sync(() => HttpRouter.toWebHandler(app.routes, { disableLogger: true })),
          (web) => Effect.promise(() => web.dispose()),
        );

        const send = (request: Request) => Effect.promise(() => web.handler(request));

        const begin = yield* send(
          new Request("https://app.test/auth/start", {
            method: "POST",
            headers: {
              origin: "https://app.test",
              "content-type": "application/json",
              "x-effect-auth-csrf": "1",
            },
            body: JSON.stringify({
              payload: {
                provider: "github",
                returnTarget: "/account",
              },
            }),
          }),
        );

        expect(begin.status).toBe(200);
        const body = yield* Effect.promise(() => begin.text());

        const started = yield* Schema.decodeEffect(
          Schema.fromJsonString(
            Schema.Struct({
              value: contract.actions.start.route.operation.rpc.successSchema,
            }),
          ),
        )(body);

        expect(app.begun[0]!.flowId).toBe(started.value.flowId);
        expect(app.begun[0]!.commandId).not.toBe(app.begun[0]!.flowId);
        const local = yield* app.localSignIn;

        expect(local.flowId).not.toBe(started.value.flowId);
        expect(app.begun[1]!.commandId).not.toBe(app.begun[0]!.commandId);

        const authorization = new URL(Redacted.value(started.value.authorizationUrl));

        const callback = custom
          ? "https://app.test/custom/github"
          : "https://app.test/auth/github/callback";

        expect(authorization.searchParams.get("redirect_uri")).toBe(callback);
        expect(app.http.oauth.callbackUrl("github")).toBe(callback);
        const cookies = begin.headers.getSetCookie();

        expect(cookies).toHaveLength(1);
        expect(cookies[0]).toContain("HttpOnly");
        const cookie = cookies[0]!.split(";")[0]!;
        const url = `${callback}?state=${authorization.searchParams.get("state")}&code=private-code&iss=https%3A%2F%2Fgithub.com%2Flogin%2Foauth`;

        for (const request of [
          new Request(url),
          new Request(`${url}&state=duplicate`, { headers: { cookie } }),
          new Request(`${url}&flowId=attacker`, { headers: { cookie } }),
          new Request(url, { headers: { cookie: `${cookie.slice(0, -2)}xx` } }),
          new Request("https://app.test/auth/finish", { method: "POST", headers: { cookie } }),
        ]) {
          const rejected = yield* send(request);

          expect(rejected.status).toBeGreaterThanOrEqual(400);
        }
        expect(app.completed).toHaveLength(0);

        const response = yield* send(new Request(url, { headers: { cookie } }));

        expect(response.status).toBe(custom ? 200 : 303);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(
          response.headers
            .getSetCookie()
            .some((value) => value.includes("private-session") && value.includes("HttpOnly")),
        ).toBe(true);
        if (custom)
          expect(yield* Effect.promise(() => response.text())).toBe("Continue registration");
        else expect(response.headers.get("location")).toBe("https://app.test/account");
        expect(app.completed).toHaveLength(1);
        expect(app.completed[0]!.flowId).toBe(started.value.flowId);
        expect(app.completed[0]!.provider).toBe("github");
        expect(app.completed[0]!.callbackId).toBe(custom ? "custom-github" : "github");
        expect(body).not.toContain(cookie.split("=")[1]);
      }
    }),
);
