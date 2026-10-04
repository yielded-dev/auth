import { it } from "@effect/vitest";
import * as GitHub from "@yielded/auth/GitHub";
import {
  OAuthCallbackId,
  OAuthRedirectUri,
  OAuthIssuer,
  OAuthProviderKey,
  OAuthProtocol,
  OAuthConnectedProtocol,
  OAuthConnectedTokenContext,
  type OAuthProtocolPreparation,
} from "@yielded/auth/OAuth";
import * as OpenIdConnect from "@yielded/auth/OpenIdConnect";
import { RequestBindingFlowId } from "@yielded/auth/Operations";
import { layerCryptoWeb } from "@yielded/auth/WebCrypto";
import * as Admission from "@yielded/crypto/KdfAdmission";
import * as Portable from "@yielded/crypto/Portable";
import {
  Context,
  DateTime,
  Deferred,
  Effect,
  Exit,
  Fiber,
  Layer,
  Redacted,
  Schema,
  Scope,
} from "effect";
import { FetchHttpClient } from "effect/http";
import { describe, expect } from "vite-plus/test";

import { expectTag } from "./helpers/oauth";

const json = (body: unknown, status = 200) => Response.json(body, { status });

const platform = Layer.mergeAll(
  FetchHttpClient.layer,
  layerCryptoWeb,
  Portable.layer(globalThis.crypto.subtle).pipe(Layer.provide(Admission.layer())),
);

const loadProtocol = (options: OpenIdConnect.Options) =>
  Layer.build(OpenIdConnect.layer(options)).pipe(
    Effect.map(Context.get(OAuthProtocol)),
    Effect.provide(platform),
  );

const github = (configurationGeneration?: number, issuance?: "active" | "retired") =>
  GitHub.gitHubOAuthAppProvider({
    configurationGeneration: configurationGeneration ?? 1,
    issuance: issuance ?? "active",
    clientId: `github-${configurationGeneration ?? 1}`,
    clientSecret: Redacted.make(`github-secret-${configurationGeneration ?? 1}`),
    callbacks: [
      {
        callbackId: OAuthCallbackId.make("github"),
        redirectUri: OAuthRedirectUri.make("https://app.test/auth/github/callback"),
      },
    ],
  });

const makeTransport = (input: { readonly userResponse?: () => Response } = {}) => {
  const requests: Array<{ url: string; clientId: string | null; method: string | undefined }> = [];

  const fetch: typeof globalThis.fetch = async (request, init) => {
    const url = request instanceof Request ? request.url : String(request);

    const form =
      init?.body instanceof URLSearchParams
        ? init.body
        : new URLSearchParams(
            typeof init?.body === "string"
              ? init.body
              : init?.body instanceof Uint8Array
                ? new TextDecoder().decode(init.body)
                : "",
          );

    requests.push({ url, clientId: form.get("client_id"), method: init?.method });
    if (url === "https://github.com/login/oauth/access_token")
      return json({
        access_token: "github-token-never-returned",
        token_type: "bearer",
        scope: "read:user",
      });
    if (url === "https://api.github.com/user")
      return (
        input.userResponse?.() ??
        json({ id: 42, login: "octocat", email: "untrusted-profile@example.test" })
      );
    throw new Error("Unexpected endpoint");
  };

  return { fetch, requests };
};

const begin = (protocol: OAuthProtocol["Service"], provider: "github") =>
  protocol.prepareAuthorization({
    provider: OAuthProviderKey.make(provider),
    flowId: RequestBindingFlowId.make(`flow-${provider}`),
  });

const exchange = Effect.fn("test.exchange")(function* (
  protocol: OAuthProtocol["Service"],
  started: OAuthProtocolPreparation,
) {
  return yield* protocol.exchangeVerifiedIdentity({
    configuration: started.configuration,
    secrets: started.secrets,
    verificationStartedAt: yield* DateTime.now,
    response: {
      _tag: "Code",
      state: started.secrets.state,
      code: Redacted.make("single-use-code"),
      ...(started.configuration.responseIssuerMode === "required"
        ? { issuer: started.configuration.issuer }
        : {}),
    },
  });
});

// At baseline 5199d99, invalid provider.configure input dies instead of failing in typed E.
it.effect("fails invalid GitHub provider configuration through the typed error channel", () =>
  expectTag(
    GitHub.provider({
      clientId: "invalid client id",
      clientSecret: Redacted.make("fixture-secret"),
    })
      .configure({
        provider: OAuthProviderKey.make("github"),
        callbacks: [
          {
            callbackId: OAuthCallbackId.make("github"),
            redirectUri: OAuthRedirectUri.make("https://app.test/callback"),
          },
        ],
      })
      .pipe(Effect.provide(platform)),
    "OpenIdConnectConfigurationError",
  ),
);

describe("OAuth protocol credential and resource lifetimes", () => {
  it.live(
    "finishes captured retired generations and never substitutes the active credentials",
    () =>
      Effect.gen(function* () {
        const transport = makeTransport();

        const old = yield* loadProtocol({
          providers: [github()],
          timeoutSeconds: 1,
        }).pipe(Effect.provideService(FetchHttpClient.Fetch, transport.fetch));

        const started = yield* begin(old, "github");

        const current = yield* loadProtocol({
          providers: [github(1, "retired"), github(2)],
          timeoutSeconds: 1,
        }).pipe(Effect.provideService(FetchHttpClient.Fetch, transport.fetch));

        yield* exchange(current, started);
        expect(
          transport.requests
            .filter((request) => request.method === "POST")
            .map((request) => request.clientId),
        ).toEqual(["github-1"]);
        const count = transport.requests.length;

        yield* expectTag(
          exchange(current, {
            ...started,
            configuration: {
              ...started.configuration,
              issuer: OAuthIssuer.make("https://accounts.google.com"),
            },
          }),
          "OAuthUnavailable",
        );
        yield* expectTag(
          exchange(current, {
            ...started,
            configuration: { ...started.configuration, configurationGeneration: 99 },
          }),
          "OAuthUnavailable",
        );
        expect(transport.requests).toHaveLength(count);
      }),
  );

  for (const termination of ["interruption", "timeout"]) {
    it.live(`${termination} cancels an acquired response body without repeating the exchange`, () =>
      Effect.gen(function* () {
        const reading = yield* Deferred.make<void>();
        let cancelled = false;

        const transport = makeTransport({
          userResponse: () =>
            new Response(
              new ReadableStream(
                {
                  pull() {
                    Deferred.doneUnsafe(reading, Effect.void);
                  },
                  cancel() {
                    cancelled = true;
                  },
                },
                { highWaterMark: 0 },
              ),
              { headers: { "content-type": "application/json" } },
            ),
        });

        const protocol = yield* loadProtocol({
          providers: [github()],
          timeoutSeconds: 1,
        }).pipe(Effect.provideService(FetchHttpClient.Fetch, transport.fetch));

        const started = yield* begin(protocol, "github");
        const fiber = yield* exchange(protocol, started).pipe(Effect.forkChild);

        yield* Deferred.await(reading);
        if (termination === "interruption") yield* Fiber.interrupt(fiber);
        else yield* expectTag(Fiber.join(fiber), "OAuthUnavailable");
        expect(cancelled).toBe(true);
        expect(transport.requests.filter((request) => request.method === "POST")).toHaveLength(1);
      }),
    );
  }
});

it.live("inspects GitHub's raw expiry and terminal receipt before token normalization", () =>
  Effect.gen(function* () {
    let receipt: unknown = { error: "bad_verification_code" };
    let calls = 0;
    const transport = makeTransport();

    const fetch: typeof globalThis.fetch = async (request, init) => {
      const url = request instanceof Request ? request.url : String(request);

      if (url === "https://github.com/login/oauth/access_token") {
        calls++;

        return json(receipt);
      }

      return transport.fetch(request, init);
    };

    const protocol = yield* loadProtocol({ providers: [github()], timeoutSeconds: 1 }).pipe(
      Effect.provideService(FetchHttpClient.Fetch, fetch),
    );

    const started = yield* begin(protocol, "github");

    yield* expectTag(exchange(protocol, started), "OAuthProtocolRejected");
    receipt = {
      access_token: "access",
      token_type: "bearer",
      scope: "read:user",
      expires_in: "3600",
    };
    yield* expectTag(exchange(protocol, started), "OAuthUnavailable");
    expect(calls).toBe(2);
    expect(transport.requests).toHaveLength(0);
    yield* expectTag(
      protocol.exchangeVerifiedIdentity({
        configuration: started.configuration,
        secrets: started.secrets,
        verificationStartedAt: yield* DateTime.now,
        response: {
          _tag: "Code",
          state: Redacted.make("a".repeat(43)),
          code: Redacted.make("code"),
          issuer: started.configuration.issuer,
        },
      }),
      "OAuthProtocolRejected",
    );
    expect(calls).toBe(2);
  }),
);

it.live("owns GitHub cohort revocation until its provider scope closes", () =>
  Effect.gen(function* () {
    const owner = yield* Scope.fork(yield* Effect.scope);

    const sent = yield* Deferred.make<void>();
    let deletes = 0;
    let aborted = false;
    let suspend = false;

    const transport = makeTransport();

    const fetch: typeof globalThis.fetch = async (request, init) => {
      const url = request instanceof Request ? request.url : String(request);

      if (url === "https://github.com/login/oauth/access_token")
        return json({
          access_token: "access",
          refresh_token: "refresh",
          token_type: "bearer",
          scope: "read:user",
          expires_in: 3600,
          refresh_token_expires_in: 7200,
        });
      if (url === "https://api.github.com/applications/client/grant") {
        deletes++;
        expect(init?.method).toBe("DELETE");
        if (!suspend) return new Response(null, { status: 204 });

        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            "abort",
            () => {
              aborted = true;
              reject(new DOMException("Closed provider", "AbortError"));
            },
            { once: true },
          );
          Deferred.doneUnsafe(sent, Effect.void);
        });
      }

      return transport.fetch(request, init);
    };

    const profile = GitHub.accessProfile({ clientId: "client" });

    const services = yield* Layer.buildWithScope(
      GitHub.layerConnected({
        clientId: "client",
        clientSecret: Redacted.make("secret"),
        redirectUri: "https://app.test/callback",
        profiles: [profile],
      }).pipe(Layer.provide(platform)),
      owner,
    ).pipe(Effect.provideService(FetchHttpClient.Fetch, fetch));

    const protocol = Context.get(services, OAuthConnectedProtocol);

    const began = yield* protocol.prepareAuthorization({
      profile,
      callbackId: OAuthCallbackId.make("github"),
      flowId: RequestBindingFlowId.make("flow"),
    });

    const now = yield* DateTime.now;

    const grant = yield* protocol.exchangeGrant({
      configuration: began.configuration,
      secrets: began.secrets,
      verificationStartedAt: now,
      response: {
        _tag: "Code",
        code: Redacted.make("code"),
        state: began.secrets.state,
        issuer: began.configuration.issuer,
      },
    });

    const start = DateTime.toEpochMillis(now);

    const context = yield* Schema.decodeUnknownEffect(Schema.toType(OAuthConnectedTokenContext))({
      namespace: "effect-auth/oauth-connected-token-context/v1",
      exchangeOrder: "1",
      moduleId: "oauth",
      subjectId: "subject",
      identity: grant.identity,
      configuration: began.configuration,
      grantId: "grant",
      grantVersion: "1",
      tokenVersion: "1",
      cohortGeneration: "1",
      metadata: {
        scopes: grant.scopes,
        resources: grant.resources,
        accessExpiresAtMillis: grant.accessExpiresAtMillis,
        useUntilMillis: start + 100000,
        refreshUseUntilMillis: start + 200000,
        obtainedAtMillis: start,
      },
    });

    const revoke = protocol.revokeGrant({ context, material: grant.material });

    expect(yield* revoke).toBe("Confirmed");
    suspend = true;

    const active = yield* Effect.forkChild(revoke);

    yield* Deferred.await(sent);
    yield* Scope.close(owner, Exit.void);
    expect(aborted).toBe(true);
    yield* expectTag(Fiber.join(active), "OAuthUnavailable");
    yield* expectTag(revoke, "OAuthUnavailable");
    expect(deletes).toBe(2);
  }),
);
