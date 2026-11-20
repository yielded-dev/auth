import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
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
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Jwt from "effect/jose/Jwt";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Scope from "effect/Scope";
import * as TestClock from "effect/testing/TestClock";
import { describe, expect } from "vite-plus/test";

import { makeProfileFetch } from "../../src/oauth/providers/shared/profileFetch";
import { expectTag } from "./helpers/oauth";

const json = (body: unknown, status = 200) => Response.json(body, { status });

const platform = Layer.mergeAll(FetchHttpClient.layer, NodeCrypto.layer);

const loadProtocol = (options: OpenIdConnect.Options) =>
  Layer.build(OpenIdConnect.layer(options)).pipe(
    Effect.map(Context.get(OAuthProtocol)),
    Effect.provide(platform),
  );

const github = (
  configurationGeneration?: number,
  issuance?: "active" | "retired",
  verifiedPrimaryEmail = false,
) =>
  GitHub.gitHubOAuthAppProvider({
    configurationGeneration: configurationGeneration ?? 1,
    issuance: issuance ?? "active",
    verifiedPrimaryEmail,
    clientId: `github-${configurationGeneration ?? 1}`,
    clientSecret: Redacted.make(`github-secret-${configurationGeneration ?? 1}`),
    callbacks: [
      {
        callbackId: OAuthCallbackId.make("github"),
        redirectUri: OAuthRedirectUri.make("https://app.test/auth/github/callback"),
      },
    ],
  });

const primaryEmail = { email: "private-primary@example.test", primary: true, verified: true };

const secondaryEmails = Array.from({ length: 100 }, (_, index) => ({
  email: `secondary-${index}@example.test`,
  primary: false,
  verified: true,
}));

const makeTransport = (
  input: {
    readonly userResponse?: () => Response;
    readonly emailResponse?: (url: URL) => Response;
  } = {},
) => {
  let scope = "read:user";
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
        scope,
      });
    if (url.startsWith("https://api.github.com/user/emails?")) {
      expect(url).toMatch(/^https:\/\/api\.github\.com\/user\/emails\?per_page=100&page=\d+$/u);
      expect(init?.method).toBe("GET");
      expect(init?.redirect).toMatch(/^(?:error|manual)$/u);
      expect(init?.credentials).toBe("omit");
      const headers = new Headers(init?.headers);

      expect(headers.get("authorization")).toMatch(
        /^Bearer (?:github-token-never-returned|access)$/u,
      );
      expect(headers.has("cookie")).toBe(false);
      expect(headers.has("traceparent")).toBe(false);

      return input.emailResponse?.(new URL(url)) ?? json([primaryEmail]);
    }
    if (url === "https://api.github.com/user")
      return (
        input.userResponse?.() ??
        json({ id: 42, login: "octocat", email: "untrusted-profile@example.test" })
      );
    throw new Error("Unexpected endpoint");
  };

  return {
    fetch,
    requests,
    consent: (started: OAuthProtocolPreparation) => {
      const value = new URL(Redacted.value(started.authorizationUrl)).searchParams.get("scope");

      scope = (value ?? "").replaceAll(" ", ",");

      return value;
    },
  };
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

// https://github.com/yielded-dev/auth/issues/183: /user alone omits private email.
// Native HTTP fixtures can force pagination and unsafe responses without live account access.
describe("GitHub verified primary email", () => {
  it.effect(
    "captures opt-in consent and selects the private primary across pages without changing /user",
    () =>
      Effect.gen(function* () {
        const transport = makeTransport({
          userResponse: () => json({ id: 42, login: "octocat", email: null }),
          emailResponse: (url) =>
            url.searchParams.get("page") === "1"
              ? Response.json(secondaryEmails, {
                  headers: { link: '<https://untrusted.example/emails>; rel="next"' },
                })
              : json([primaryEmail]),
        });

        const input = {
          clientId: "client",
          clientSecret: Redacted.make("fixture-secret"),
          verifiedPrimaryEmail: true,
        };

        const protocol = yield* GitHub.provider(input)
          .configure({
            provider: OAuthProviderKey.make("github"),
            callbacks: [
              {
                callbackId: OAuthCallbackId.make("github"),
                redirectUri: OAuthRedirectUri.make("https://app.test/callback"),
              },
            ],
          })
          .pipe(
            Effect.provide(platform),
            Effect.provideService(FetchHttpClient.Fetch, transport.fetch),
          );

        input.verifiedPrimaryEmail = false;
        const started = yield* begin(protocol, "github");
        const consent = transport.consent(started);
        const identity = yield* exchange(protocol, started);

        expect(identity.profile?.email).toBe(primaryEmail.email);
        expect(identity.profile?.emailVerified).toBe(true);
        expect(identity.identity.subject).toBe("42");
        expect(identity.profile?.providerData).toEqual({ id: 42, login: "octocat", email: null });
        expect(JSON.stringify(identity)).not.toContain("github-token-never-returned");
        expect(consent).toBe("read:user user:email");
        expect(transport.requests.map(({ url }) => url)).toEqual([
          "https://github.com/login/oauth/access_token",
          "https://api.github.com/user",
          "https://api.github.com/user/emails?per_page=100&page=1",
          "https://api.github.com/user/emails?per_page=100&page=2",
        ]);

        const ordinaryTransport = makeTransport();

        const ordinary = yield* loadProtocol({ providers: [github()] }).pipe(
          Effect.provideService(FetchHttpClient.Fetch, ordinaryTransport.fetch),
        );

        const ordinaryStart = yield* begin(ordinary, "github");
        const ordinaryIdentity = yield* exchange(ordinary, ordinaryStart);

        expect(ordinaryTransport.consent(ordinaryStart)).toBe("read:user");
        expect(ordinaryIdentity.profile?.email).toBe("untrusted-profile@example.test");
        expect(ordinaryIdentity.profile?.emailVerified).toBeUndefined();
        expect(ordinaryTransport.requests).toHaveLength(2);
      }),
  );

  it.effect.each([
    {
      name: "unverified primary and verified secondary",
      emails: [secondaryEmails[0], { ...primaryEmail, verified: false }],
    },
    {
      name: "ambiguous primaries",
      emails: [primaryEmail, { ...primaryEmail, email: "other-primary@example.test" }],
    },
  ])("omits normalized email for $name instead of substituting /user email", ({ emails }) =>
    Effect.gen(function* () {
      const transport = makeTransport({ emailResponse: () => json(emails) });

      const services = yield* Layer.build(
        GitHub.layer({
          clientId: "client",
          clientSecret: Redacted.make("fixture-secret"),
          redirectUri: "https://app.test/callback",
          verifiedPrimaryEmail: true,
        }),
      ).pipe(
        Effect.provide(platform),
        Effect.provideService(FetchHttpClient.Fetch, transport.fetch),
      );

      const protocol = Context.get(services, OAuthProtocol);
      const started = yield* begin(protocol, "github");

      transport.consent(started);
      const identity = yield* exchange(protocol, started);

      expect(identity.profile).not.toHaveProperty("email");
      expect(identity.profile).not.toHaveProperty("emailVerified");
      expect(identity.profile?.providerData?.email).toBe("untrusted-profile@example.test");
      expect(identity.identity.subject).toBe("42");
      expect(transport.requests).toHaveLength(3);
    }),
  );

  it.effect.each([
    {
      name: "unterminated pagination",
      response: () => json(secondaryEmails),
      requests: 12,
      tag: "OAuthUnavailable" as const,
    },
    {
      name: "oversized body",
      response: () =>
        new Response("x".repeat(65_537), { headers: { "content-type": "application/json" } }),
      requests: 3,
      tag: "OAuthUnavailable" as const,
    },
    {
      name: "redirect",
      response: () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://untrusted.example/emails" },
        }),
      requests: 3,
      tag: "OAuthUnavailable" as const,
    },
    {
      name: "malformed verification flag",
      response: () => json([{ ...primaryEmail, verified: "true" }]),
      requests: 3,
      tag: "OAuthProtocolRejected" as const,
    },
  ])("rejects $name without repeating the exchange", (failure) =>
    Effect.gen(function* () {
      const transport = makeTransport({ emailResponse: failure.response });

      const protocol = yield* loadProtocol({ providers: [github(1, "active", true)] }).pipe(
        Effect.provideService(FetchHttpClient.Fetch, transport.fetch),
      );

      const started = yield* begin(protocol, "github");

      transport.consent(started);
      yield* expectTag(exchange(protocol, started), failure.tag);
      expect(transport.requests).toHaveLength(failure.requests);
      expect(transport.requests.filter(({ method }) => method === "POST")).toHaveLength(1);
    }),
  );

  it.effect("requires explicit email permission in retained access profiles", () =>
    expectTag(
      Layer.build(
        GitHub.layerConnected({
          clientId: "client",
          clientSecret: Redacted.make("fixture-secret"),
          redirectUri: "https://app.test/callback",
          verifiedPrimaryEmail: true,
          profiles: [GitHub.accessProfile({ clientId: "client" })],
        }),
      ).pipe(Effect.provide(platform)),
      "OpenIdConnectConfigurationError",
    ),
  );
});

describe("OAuth protocol credential and resource lifetimes", () => {
  // At 28374b35, owner closure left application identity decoding running after HTTP completed.
  it.effect("joins identity decoder cleanup when its provider scope closes", () =>
    Effect.gen(function* () {
      const owner = yield* Scope.fork(yield* Effect.scope);
      const entered = yield* Deferred.make<void>();
      const resume = yield* Deferred.make<void>();
      const cleanup = yield* Deferred.make<void>();
      let interrupted = false;
      const provider = github();
      const transport = makeTransport();

      const services = yield* Layer.buildWithScope(
        OpenIdConnect.layer({
          providers: [
            {
              ...provider,
              identitySource: {
                ...provider.identitySource,
                decodeIdentity: () =>
                  Deferred.succeed(entered, undefined).pipe(
                    Effect.andThen(Deferred.await(resume)),
                    Effect.as({ subject: "42" }),
                    Effect.onInterrupt(() =>
                      Effect.sync(() => {
                        interrupted = true;
                      }),
                    ),
                    Effect.ensuring(Deferred.await(cleanup)),
                  ),
              },
            },
          ],
        }).pipe(Layer.provide(platform)),
        owner,
      ).pipe(Effect.provideService(FetchHttpClient.Fetch, transport.fetch));

      const protocol = Context.get(services, OAuthProtocol);
      const started = yield* begin(protocol, "github");
      const active = yield* exchange(protocol, started).pipe(Effect.result, Effect.forkChild);

      yield* Deferred.await(entered);
      const closing = yield* Scope.close(owner, Exit.void).pipe(Effect.forkChild);

      yield* TestClock.adjust(1);
      const closeBeforeCleanup = closing.pollUnsafe();
      const interruptedBeforeCleanup = interrupted;

      yield* Deferred.succeed(resume, undefined);
      yield* Deferred.succeed(cleanup, undefined);
      yield* Fiber.join(closing);
      const result = yield* Fiber.join(active);

      expect(result).toMatchObject({ _tag: "Failure", failure: { _tag: "OAuthUnavailable" } });
      expect(interruptedBeforeCleanup).toBe(true);
      expect(closeBeforeCleanup).toBeUndefined();
      yield* expectTag(exchange(protocol, started), "OAuthUnavailable");
    }),
  );

  it.live(
    "finishes captured retired generations and never substitutes the active credentials",
    () =>
      Effect.gen(function* () {
        const transport = makeTransport();

        const old = yield* loadProtocol({
          providers: [github(1, "active", true)],
          timeoutSeconds: 1,
        }).pipe(Effect.provideService(FetchHttpClient.Fetch, transport.fetch));

        const started = yield* begin(old, "github");

        transport.consent(started);

        const current = yield* loadProtocol({
          providers: [github(1, "retired", true), github(2)],
          timeoutSeconds: 1,
        }).pipe(Effect.provideService(FetchHttpClient.Fetch, transport.fetch));

        const identity = yield* exchange(current, started);

        expect(identity.profile?.email).toBe(primaryEmail.email);
        expect(identity.profile?.emailVerified).toBe(true);
        expect(
          new URL(
            Redacted.value((yield* begin(current, "github")).authorizationUrl),
          ).searchParams.get("scope"),
        ).toBe("read:user");
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
    it.live(`${termination} cancels the private email body without repeating the exchange`, () =>
      Effect.gen(function* () {
        const reading = yield* Deferred.make<void>();
        let cancelled = false;

        const transport = makeTransport({
          emailResponse: () =>
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
          providers: [github(1, "active", true)],
          timeoutSeconds: 1,
        }).pipe(Effect.provideService(FetchHttpClient.Fetch, transport.fetch));

        const started = yield* begin(protocol, "github");

        transport.consent(started);
        const fiber = yield* exchange(protocol, started).pipe(Effect.forkChild);

        const reached = yield* Effect.raceFirst(
          Deferred.await(reading).pipe(Effect.as("reading")),
          Fiber.await(fiber).pipe(Effect.as("completed")),
        );

        expect(reached).toBe("reading");
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
          scope: "read:user,user:email",
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

    const profile = GitHub.accessProfile({
      clientId: "client",
      scopes: ["read:user", "user:email"],
    });

    const services = yield* Layer.buildWithScope(
      GitHub.layerConnected({
        clientId: "client",
        clientSecret: Redacted.make("secret"),
        redirectUri: "https://app.test/callback",
        profiles: [profile],
        verifiedPrimaryEmail: true,
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

    expect(grant.identity.subject).toBe("42");
    expect(grant.profile?.email).toBe(primaryEmail.email);
    expect(grant.profile?.emailVerified).toBe(true);
    expect(grant.scopes).toEqual(["read:user", "user:email"]);
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

const entraHost = "https://login.microsoftonline.com";
const entraV1Host = "https://sts.windows.net";
const ciamHost = "https://contoso.ciamlogin.com";
const genericTenantHost = "https://idp.example";
const entraTemplate = `${entraHost}/{tenantid}/v2.0`;
const workTenant = "11111111-1111-1111-1111-111111111111";
const otherWorkTenant = "22222222-2222-2222-2222-222222222222";
const personalTenant = "9188040d-6c67-4c5b-b112-36a304b66dad";
const uppercasePersonalTenant = personalTenant.toUpperCase();

interface EntraDiscoveryCase {
  readonly name: string;
  readonly host: string;
  readonly authority: string;
  readonly v1?: boolean;
  readonly discoveryIssuer: string;
  readonly tokenIssuer: string;
  readonly tid: string;
  readonly expectedSubject: string;
  readonly keys: ReadonlyArray<{
    readonly keyIssuer: string | undefined;
    readonly tid?: string;
    readonly accepted: boolean;
  }>;
}

it.effect.each<EntraDiscoveryCase>([
  // Regression at 25217c71: pinning a discovery template admitted an issuer-less key.
  {
    name: "requires key issuer authority for a pinned tenant template",
    host: entraHost,
    authority: workTenant,
    discoveryIssuer: entraTemplate,
    tokenIssuer: `${entraHost}/${workTenant}/v2.0`,
    tid: workTenant,
    expectedSubject: "provider-subject",
    keys: [
      { keyIssuer: undefined, accepted: false },
      { keyIssuer: entraTemplate, accepted: true },
    ],
  },
  // Regression at 881f94d: organizations admitted a personal account after template matching.
  {
    name: "definitely rejects personal accounts on organizations",
    host: entraHost,
    authority: "organizations",
    discoveryIssuer: entraTemplate,
    tokenIssuer: `${entraHost}/${uppercasePersonalTenant}/v2.0`,
    tid: uppercasePersonalTenant,
    expectedSubject: `${personalTenant}:provider-subject`,
    keys: [{ keyIssuer: `${entraHost}/${uppercasePersonalTenant}/v2.0`, accepted: false }],
  },
  // Regression at 881f94d: concrete consumers discovery admitted an issuer-less key.
  {
    name: "requires key issuer authority for concrete consumers discovery",
    host: entraHost,
    authority: "consumers",
    discoveryIssuer: `${entraHost}/${personalTenant}/v2.0`,
    tokenIssuer: `${entraHost}/${personalTenant}/v2.0`,
    tid: personalTenant,
    expectedSubject: `${personalTenant}:provider-subject`,
    keys: [
      { keyIssuer: undefined, accepted: false },
      { keyIssuer: `${entraHost}/${personalTenant}/v2.0`, accepted: true },
      {
        keyIssuer: `${entraHost}/${personalTenant}/v2.0`,
        tid: uppercasePersonalTenant,
        accepted: true,
      },
    ],
  },
  // Regression at 881f94d (carried into 0609a81): pinned consumers with a concrete
  // JWK issuer never compared signed tid with the pinned tenant GUID before
  // building the tenant-namespaced subject.
  {
    name: "rejects mismatched tid on pinned consumers discovery",
    host: entraHost,
    authority: "consumers",
    discoveryIssuer: `${entraHost}/${personalTenant}/v2.0`,
    tokenIssuer: `${entraHost}/${personalTenant}/v2.0`,
    tid: workTenant,
    expectedSubject: `${workTenant}:provider-subject`,
    keys: [{ keyIssuer: `${entraHost}/${personalTenant}/v2.0`, accepted: false }],
  },
  // Regression at 881f94d (carried into 0609a81): pinned single-tenant GUID with
  // a concrete JWK issuer never compared signed tid with the pinned tenant GUID.
  {
    name: "rejects mismatched tid on pinned single-tenant discovery",
    host: entraHost,
    authority: workTenant,
    discoveryIssuer: entraTemplate,
    tokenIssuer: `${entraHost}/${workTenant}/v2.0`,
    tid: otherWorkTenant,
    expectedSubject: "provider-subject",
    keys: [{ keyIssuer: `${entraHost}/${workTenant}/v2.0`, accepted: false }],
  },
  // Regression at 881f94d (still open on ba2baeb): exact-match concrete Entra
  // authorities (including Microsoft.provider({ tenant: "consumers" }), which
  // rewrites consumers to the personal-account GUID before discovery) returned
  // pinned: false with no expectedTenantId, admitting issuer-less keys and forged tid.
  {
    name: "pins exact-match concrete Entra personal-account authority and checks tid case-insensitively",
    host: entraHost,
    authority: personalTenant,
    discoveryIssuer: `${entraHost}/${personalTenant}/v2.0`,
    tokenIssuer: `${entraHost}/${personalTenant}/v2.0`,
    tid: uppercasePersonalTenant,
    expectedSubject: "provider-subject",
    keys: [
      { keyIssuer: undefined, accepted: false },
      { keyIssuer: `${entraHost}/${personalTenant}/v2.0`, tid: workTenant, accepted: false },
      { keyIssuer: `${entraHost}/${personalTenant}/v2.0`, accepted: true },
    ],
  },
  // Regression at 881f94d (still open on ba2baeb): exact-match Entra External ID
  // (*.ciamlogin.com) concrete tenant authorities must also pin key authority and tid.
  {
    name: "pins exact-match CIAM concrete tenant authority",
    host: ciamHost,
    authority: workTenant,
    discoveryIssuer: `${ciamHost}/${workTenant}/v2.0`,
    tokenIssuer: `${ciamHost}/${workTenant}/v2.0`,
    tid: workTenant,
    expectedSubject: "provider-subject",
    keys: [
      { keyIssuer: undefined, accepted: false },
      { keyIssuer: `${ciamHost}/${workTenant}/v2.0`, tid: otherWorkTenant, accepted: false },
      { keyIssuer: `${ciamHost}/${workTenant}/v2.0`, accepted: true },
    ],
  },
  // Entra v1 (sts.windows.net/<tenant>/) JWKS omits per-key issuer, so valid v1
  // sign-ins must succeed while still binding tid to the concrete tenant GUID.
  {
    name: "accepts Entra v1 JWKS without key issuer while binding tid",
    host: entraV1Host,
    authority: workTenant,
    v1: true,
    discoveryIssuer: `${entraV1Host}/${workTenant}/`,
    tokenIssuer: `${entraV1Host}/${workTenant}/`,
    tid: workTenant,
    expectedSubject: "provider-subject",
    keys: [
      { keyIssuer: undefined, accepted: true },
      { keyIssuer: undefined, tid: otherWorkTenant, accepted: false },
      { keyIssuer: `${entraV1Host}/${otherWorkTenant}/`, accepted: false },
    ],
  },
  // Generic {tenantid} OIDC registrations keep exact tid casing in their subject
  // namespace and compare pinned tenant IDs case-sensitively.
  {
    name: "preserves exact tid casing on generic multi-tenant OIDC registrations",
    host: genericTenantHost,
    authority: "common",
    discoveryIssuer: `${genericTenantHost}/{tenantid}/v2.0`,
    tokenIssuer: `${genericTenantHost}/${uppercasePersonalTenant}/v2.0`,
    tid: uppercasePersonalTenant,
    expectedSubject: `${uppercasePersonalTenant}:provider-subject`,
    keys: [{ keyIssuer: `${genericTenantHost}/${uppercasePersonalTenant}/v2.0`, accepted: true }],
  },
  {
    name: "checks pinned tid case-sensitively on generic OIDC registrations",
    host: genericTenantHost,
    authority: personalTenant,
    discoveryIssuer: `${genericTenantHost}/{tenantid}/v2.0`,
    tokenIssuer: `${genericTenantHost}/${personalTenant}/v2.0`,
    tid: personalTenant,
    expectedSubject: "provider-subject",
    keys: [
      {
        keyIssuer: `${genericTenantHost}/${personalTenant}/v2.0`,
        tid: uppercasePersonalTenant,
        accepted: false,
      },
      { keyIssuer: `${genericTenantHost}/${personalTenant}/v2.0`, accepted: true },
    ],
  },
])(
  "Entra discovery $name",
  ({ host, authority, v1, discoveryIssuer, tokenIssuer, tid, expectedSubject, keys }) =>
    Effect.gen(function* () {
      const seconds = 2_000_000_000;

      yield* TestClock.setTime(seconds * 1000);
      const pair = yield* Jwk.generateKeyPair({ algorithm: "ES256", kid: "key" });
      const signingKey = yield* Jwk.importPrivate(pair.privateKey, "ES256");
      const configuredIssuer = v1 ? `${host}/${authority}/` : `${host}/${authority}/v2.0`;

      const endpoints = v1
        ? {
            discovery: `${host}/${authority}/.well-known/openid-configuration`,
            authorization: `${entraHost}/${authority}/oauth2/authorize`,
            token: `${entraHost}/${authority}/oauth2/token`,
            jwks: `${entraHost}/${authority}/discovery/keys`,
          }
        : {
            discovery: `${configuredIssuer}/.well-known/openid-configuration`,
            authorization: `${host}/${authority}/oauth2/v2.0/authorize`,
            token: `${host}/${authority}/oauth2/v2.0/token`,
            jwks: `${host}/${authority}/discovery/v2.0/keys`,
          };

      const EntraIdToken = Schema.Struct({
        iss: Schema.String,
        sub: Schema.String,
        aud: Schema.String,
        azp: Schema.String,
        iat: Schema.Finite,
        exp: Schema.Finite,
        nonce: Schema.String,
        tid: Schema.String,
      });

      for (const entry of keys) {
        const { keyIssuer, accepted } = entry;
        const tokenTid = "tid" in entry && entry.tid !== undefined ? entry.tid : tid;
        let idToken = "";

        const fetch: typeof globalThis.fetch = async (input) => {
          const url = input instanceof Request ? input.url : String(input);

          if (url === endpoints.discovery) {
            return json({
              issuer: discoveryIssuer,
              ...(v1 ? {} : { signing_key_issuer_required: false }),
              authorization_endpoint: endpoints.authorization,
              token_endpoint: endpoints.token,
              jwks_uri: endpoints.jwks,
              response_types_supported: ["code"],
              code_challenge_methods_supported: ["S256"],
              id_token_signing_alg_values_supported: ["ES256"],
              token_endpoint_auth_methods_supported: ["client_secret_basic"],
            });
          }
          if (url === endpoints.token) {
            return json({
              access_token: "private-access",
              token_type: "bearer",
              id_token: idToken,
            });
          }
          if (url === endpoints.jwks) {
            return json({
              keys: [
                {
                  ...pair.publicKey,
                  ...(keyIssuer === undefined ? {} : { issuer: keyIssuer }),
                },
              ],
            });
          }
          throw new Error(`Unexpected endpoint ${url}`);
        };

        const protocol = yield* loadProtocol({
          providers: [
            {
              protocol: "oidc",
              provider: OAuthProviderKey.make("entra"),
              issuer: OAuthIssuer.make(configuredIssuer),
              responseIssuerMode: "unsupported",
              clientId: "client",
              clientSecret: Redacted.make("client-secret"),
              redirectUri: OAuthRedirectUri.make("https://app.test/auth/entra/callback"),
              idTokenSignedResponseAlg: ["ES256"],
            },
          ],
        }).pipe(Effect.provideService(FetchHttpClient.Fetch, fetch));

        const started = yield* protocol.prepareAuthorization({
          provider: OAuthProviderKey.make("entra"),
          flowId: RequestBindingFlowId.make("flow-entra"),
        });

        if (started.secrets.oidcNonce === undefined) {
          throw new Error("Expected OIDC nonce");
        }

        idToken = Redacted.value(
          yield* Jwt.sign(
            EntraIdToken,
            {
              iss: tokenIssuer,
              sub: "provider-subject",
              aud: "client",
              azp: "client",
              iat: seconds,
              exp: seconds + 300,
              nonce: Redacted.value(started.secrets.oidcNonce),
              tid: tokenTid,
            },
            signingKey,
          ),
        );

        const completed = yield* protocol
          .exchangeVerifiedIdentity({
            configuration: started.configuration,
            secrets: started.secrets,
            verificationStartedAt: DateTime.makeUnsafe(seconds * 1000),
            response: {
              _tag: "Code",
              state: started.secrets.state,
              code: Redacted.make("single-use-code"),
            },
          })
          .pipe(Effect.provideService(FetchHttpClient.Fetch, fetch), Effect.result);

        expect(completed).toMatchObject(
          accepted
            ? {
                _tag: "Success",
                success: { identity: { subject: expectedSubject, issuer: configuredIssuer } },
              }
            : { _tag: "Failure", failure: { _tag: "OAuthProtocolRejected" } },
        );
      }
    }).pipe(Effect.provide(platform)),
);

// Relocated from packages/oauth/test/protocol.test.ts along with plain-OAuth profileFetch:
// profile URL loopback anti-downgrade, bearer + custom headers, and pre-dispatch header-injection checks.
it.effect(
  "enforces profile URL loopback anti-downgrade, bearer/custom headers, and header-injection checks",
  () =>
    Effect.gen(function* () {
      const requests: Array<{
        readonly url: string;
        readonly authorization: string | null;
        readonly apiVersion: string | null;
      }> = [];

      const fetch: typeof globalThis.fetch = async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);

        const headers = new Headers(
          init?.headers ?? (input instanceof Request ? input.headers : undefined),
        );

        requests.push({
          url,
          authorization: headers.get("authorization"),
          apiVersion: headers.get("x-api-version"),
        });

        return json({ id: 42 });
      };

      const provideFetch = Effect.provideService(FetchHttpClient.Fetch, fetch);

      expect(
        yield* makeProfileFetch({
          issuer: "https://issuer.example/tenant/",
          url: "http://localhost:8080/user",
          timeoutMs: 1000,
        }).pipe(provideFetch, Effect.flip),
      ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });

      expect(
        yield* makeProfileFetch({
          issuer: "https://issuer.example/tenant/",
          url: "https://api.example/user",
          headers: { Authorization: "injected" },
          timeoutMs: 1000,
        }).pipe(provideFetch, Effect.flip),
      ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });

      expect(requests).toEqual([]);

      const loopbackProfile = yield* makeProfileFetch({
        issuer: "http://127.0.0.1:8080",
        url: "http://localhost:8080/user",
        timeoutMs: 1000,
      }).pipe(provideFetch);

      expect(yield* loopbackProfile(Redacted.make("private-access"))).toEqual({ id: 42 });

      const httpsProfile = yield* makeProfileFetch({
        issuer: "https://issuer.example/tenant/",
        url: "https://api.example/user",
        headers: { "X-Api-Version": "2026" },
        timeoutMs: 1000,
      }).pipe(provideFetch);

      expect(yield* httpsProfile(Redacted.make("private-access"))).toEqual({ id: 42 });
      expect(requests).toEqual([
        {
          url: "http://localhost:8080/user",
          authorization: "Bearer private-access",
          apiVersion: null,
        },
        {
          url: "https://api.example/user",
          authorization: "Bearer private-access",
          apiVersion: "2026",
        },
      ]);
    }).pipe(Effect.scoped, Effect.provide(FetchHttpClient.layer)),
);
