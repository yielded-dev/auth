import { generateKeyPairSync, sign } from "node:crypto";

import { it } from "@effect/vitest";
import * as GitHub from "@yielded/auth/GitHub";
import {
  OAuthCallbackId,
  OAuthRedirectUri,
  OAuthIssuer,
  OAuthProviderKey,
  OAuthProtocol,
  type OAuthProtocolPreparation,
} from "@yielded/auth/OAuth";
import * as OpenIdClient from "@yielded/auth/OpenIdClient";
import { RequestBindingFlowId } from "@yielded/auth/Operations";
import { DateTime, Deferred, Effect, Fiber, Redacted, Schema } from "effect";
import type { CustomFetch } from "openid-client";
import { describe, expect } from "vite-plus/test";

import { githubProfile, normalizedGithubProfile } from "../../fixtures/github-profile";
import { expectTag } from "../../helpers/oauth";

const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: "jwk" }), kid: "test", alg: "RS256", use: "sig" };

const jwt = (claims: Record<string, unknown>) => {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${payload}`;

  return `${input}.${sign("RSA-SHA256", Buffer.from(input), keys.privateKey).toString("base64url")}`;
};

const json = (body: unknown, status = 200) => Response.json(body, { status });
const googleIssuer = OAuthIssuer.make("https://accounts.google.com");

const loadProtocol = (options: OpenIdClient.Options) =>
  OAuthProtocol.pipe(Effect.provide(OpenIdClient.layer(options)));

const loadGitHubProtocol = (options: GitHub.Options) =>
  OAuthProtocol.pipe(Effect.provide(GitHub.layer(options)));

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

const google = (configurationGeneration?: number, issuance?: "active" | "retired") =>
  ({
    provider: "google",
    protocol: "oidc",
    ...(configurationGeneration === undefined ? {} : { configurationGeneration }),
    ...(issuance === undefined ? {} : { issuance }),
    issuer: googleIssuer,
    clientId: `google-${configurationGeneration ?? 1}`,
    clientSecret: Redacted.make(`google-secret-${configurationGeneration ?? 1}`),
    tokenEndpointAuthMethod: "client_secret_post",
    redirectUri: "https://app.test/auth/google/callback",
  }) satisfies OpenIdClient.Provider;

const makeTransport = (
  input: {
    readonly claims?: Record<string, unknown>;
    readonly tokenResponse?: () => Response;
    readonly userResponse?: () => Response;
  } = {},
) => {
  const requests: Array<{ url: string; clientId: string | null; method: string | undefined }> = [];
  let nonce = "";

  const fetch: CustomFetch = async (url, init) => {
    const form = init.body instanceof URLSearchParams ? init.body : new URLSearchParams();

    requests.push({ url, clientId: form.get("client_id"), method: init.method });
    if (url === "https://accounts.google.com/.well-known/openid-configuration")
      return json({
        issuer: googleIssuer,
        authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint: "https://oauth2.googleapis.com/token",
        jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
        authorization_response_iss_parameter_supported: true,
      });
    if (url === "https://www.googleapis.com/oauth2/v3/certs") return json({ keys: [jwk] });
    if (url === "https://oauth2.googleapis.com/token") {
      const now = Math.floor(Date.now() / 1000);

      return json({
        access_token: "google-token-never-returned",
        token_type: "bearer",
        id_token: jwt({
          iss: googleIssuer,
          sub: "stable-google-sub",
          aud: form.get("client_id"),
          iat: now,
          exp: now + 600,
          nonce,
          name: "Google Member",
          ...input.claims,
        }),
      });
    }
    if (url === "https://github.com/login/oauth/access_token")
      return (
        input.tokenResponse?.() ??
        json({
          access_token: "github-token-never-returned",
          token_type: "bearer",
          scope: "read:user",
        })
      );
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
    setNonce: (started: OAuthProtocolPreparation) => {
      nonce = Redacted.value(started.secrets.oidcNonce!);
    },
  };
};

const begin = (protocol: OAuthProtocol["Service"], provider: "github" | "google") =>
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

describe("GitHub OAuth App and Google OIDC composition", () => {
  it.live(
    "retains every documented GitHub user field, nulls and false values in a detached profile",
    () =>
      Effect.gen(function* () {
        const transport = makeTransport({
          userResponse: () => json({ ...githubProfile, access_token: "must-not-be-profile-data" }),
        });

        const protocol = yield* loadProtocol({
          providers: [github()],
          timeoutSeconds: 1,
          fetch: transport.fetch,
        });

        const result = yield* exchange(protocol, yield* begin(protocol, "github"));

        expect(result.identity).toEqual({
          provider: "github",
          issuer: "https://github.com/login/oauth",
          subject: "42",
        });
        expect(result.profile).toEqual(normalizedGithubProfile);
        // oxlint-disable-next-line no-restricted-properties -- Refine the generic provider JSON with the public GitHub Schema.
        expect(
          yield* Schema.decodeUnknownEffect(GitHub.GitHubUserProfile)(
            result.profile!.providerData!,
          ),
        ).toEqual(githubProfile);
        expect(Object.isFrozen(result.profile!.providerData)).toBe(true);
        expect(Object.isFrozen(result.profile!.providerData!.plan)).toBe(true);
        expect(JSON.stringify(result)).not.toContain("must-not-be-profile-data");
        expect(JSON.stringify(result)).not.toContain("github-token-never-returned");
        expect(result.profile).not.toHaveProperty("emailVerified");
        expect(
          transport.requests.filter((request) => request.url === "https://api.github.com/user"),
        ).toHaveLength(1);
        expect(transport.requests.some((request) => request.url.includes("/emails"))).toBe(false);
      }),
  );

  for (const name of [undefined, null, "", "  "]) {
    it.live(`uses the GitHub handle when name is ${JSON.stringify(name)}`, () =>
      Effect.gen(function* () {
        const transport = makeTransport({
          userResponse: () => json({ id: 42, login: "octocat", name, email: null }),
        });

        const protocol = yield* loadProtocol({
          providers: [github()],
          timeoutSeconds: 1,
          fetch: transport.fetch,
        });

        const result = yield* exchange(protocol, yield* begin(protocol, "github"));

        expect(result.profile?.displayName).toBe("octocat");
        expect(result.profile?.handle).toBe("octocat");
        expect(result.profile?.providerData?.email).toBeNull();
        expect(result.profile).not.toHaveProperty("email");
      }),
    );
  }

  for (const profile of [
    { id: "42" },
    { id: 42, name: 1 },
    { id: 42, name: "x".repeat(257) },
    { id: 42, followers: -1 },
  ]) {
    it.live(`rejects malformed or oversized GitHub fields: ${Object.keys(profile).join(",")}`, () =>
      Effect.gen(function* () {
        const transport = makeTransport({ userResponse: () => json(profile) });

        const protocol = yield* loadProtocol({
          providers: [github()],
          timeoutSeconds: 1,
          fetch: transport.fetch,
        });

        yield* expectTag(
          exchange(protocol, yield* begin(protocol, "github")),
          "OAuthProtocolRejected",
        );
      }),
    );
  }

  it.live("retains standard OIDC user claims without protocol secrets or extra requests", () =>
    Effect.gen(function* () {
      const profile = {
        name: "Full Name",
        given_name: "Full",
        family_name: "Name",
        middle_name: "Middle",
        nickname: "Nickname",
        preferred_username: "member",
        profile: "https://provider.test/member",
        picture: "https://provider.test/avatar.png",
        website: "https://member.test",
        email: "member@example.test",
        email_verified: false,
        gender: "unspecified",
        birthdate: "2000-01-01",
        zoneinfo: "Europe/Paris",
        locale: "fr-FR",
        phone_number: "+33123456789",
        phone_number_verified: true,
        address: {
          formatted: "Example address",
          street_address: "1 Example Street",
          locality: "Paris",
          region: "IDF",
          postal_code: "75001",
          country: "FR",
        },
        updated_at: 1_700_000_000,
      };

      const transport = makeTransport({ claims: { ...profile, access_token: "not-a-user-claim" } });

      const protocol = yield* loadProtocol({
        providers: [google()],
        timeoutSeconds: 1,
        fetch: transport.fetch,
      });

      const started = yield* begin(protocol, "google");

      transport.setNonce(started);
      const result = yield* exchange(protocol, started);

      expect(result.identity.subject).toBe("stable-google-sub");
      expect(result.profile).toEqual({
        displayName: "Full Name",
        handle: "member",
        avatarUrl: profile.picture,
        profileUrl: profile.profile,
        email: profile.email,
        emailVerified: false,
        providerData: profile,
      });
      expect(
        yield* Schema.decodeEffect(OpenIdClient.OidcUserProfile)(result.profile!.providerData!),
      ).toEqual(profile);
      expect(Object.isFrozen(result.profile!.providerData!.address)).toBe(true);
      expect(result.profile?.providerData).not.toHaveProperty("nonce");
      expect(JSON.stringify(result)).not.toContain("not-a-user-claim");
      expect(JSON.stringify(result)).not.toContain("google-token-never-returned");
      expect(transport.requests.some((request) => request.url.includes("userinfo"))).toBe(false);
    }),
  );

  it.live("preserves provider profiles separately from identity without exposing tokens", () =>
    Effect.gen(function* () {
      const transport = makeTransport({
        claims: { email: "member@gmail.com", email_verified: true, preferred_username: "member" },
      });

      const protocol = yield* loadProtocol({
        providers: [github(), google()],
        timeoutSeconds: 1,
        fetch: transport.fetch,
      });

      const githubStart = yield* begin(protocol, "github");
      const googleStart = yield* begin(protocol, "google");

      transport.setNonce(googleStart);
      expect(new URL(Redacted.value(githubStart.authorizationUrl)).searchParams.get("scope")).toBe(
        "read:user",
      );
      expect(new URL(Redacted.value(googleStart.authorizationUrl)).searchParams.get("scope")).toBe(
        "openid",
      );
      for (const started of [githubStart, googleStart])
        expect(
          new URL(Redacted.value(started.authorizationUrl)).searchParams.get(
            "code_challenge_method",
          ),
        ).toBe("S256");
      expect(yield* exchange(protocol, githubStart)).toEqual({
        identity: { provider: "github", issuer: "https://github.com/login/oauth", subject: "42" },
        profile: {
          displayName: "octocat",
          handle: "octocat",
          email: "untrusted-profile@example.test",
          providerData: { id: 42, login: "octocat", email: "untrusted-profile@example.test" },
        },
      });
      expect(yield* exchange(protocol, googleStart)).toEqual({
        identity: { provider: "google", issuer: googleIssuer, subject: "stable-google-sub" },
        profile: {
          displayName: "Google Member",
          handle: "member",
          email: "member@gmail.com",
          emailVerified: true,
          providerData: {
            name: "Google Member",
            email: "member@gmail.com",
            email_verified: true,
            preferred_username: "member",
          },
        },
      });
      expect(transport.requests.filter((request) => request.url.endsWith("/user"))).toHaveLength(1);
      expect(transport.requests.some((request) => request.url.includes("emails"))).toBe(false);
    }),
  );

  it.live(
    "finishes captured retired generations and never substitutes the active credentials",
    () =>
      Effect.gen(function* () {
        const transport = makeTransport();

        const old = yield* loadProtocol({
          providers: [github(), google()],
          timeoutSeconds: 1,
          fetch: transport.fetch,
        });

        const starts = [yield* begin(old, "github"), yield* begin(old, "google")];

        const current = yield* loadProtocol({
          providers: [github(1, "retired"), github(2), google(1, "retired"), google(2)],
          timeoutSeconds: 1,
          fetch: transport.fetch,
        });

        transport.setNonce(starts[1]!);
        for (const started of starts) yield* exchange(current, started);
        expect(
          transport.requests
            .filter((request) => request.method === "POST")
            .map((request) => request.clientId),
        ).toEqual(["github-1", "google-1"]);
        expect((yield* begin(current, "github")).configuration.configurationGeneration).toBe(2);
        expect((yield* begin(current, "google")).configuration.configurationGeneration).toBe(2);
        const count = transport.requests.length;

        yield* expectTag(
          exchange(current, {
            ...starts[0]!,
            configuration: { ...starts[0]!.configuration, issuer: googleIssuer },
          }),
          "OAuthUnavailable",
        );
        yield* expectTag(
          exchange(current, {
            ...starts[0]!,
            configuration: { ...starts[0]!.configuration, configurationGeneration: 99 },
          }),
          "OAuthUnavailable",
        );
        expect(transport.requests).toHaveLength(count);
      }),
  );

  it.live(
    "rejects duplicate provider generations and shared callbacks without issuer responses",
    () =>
      Effect.gen(function* () {
        const transport = makeTransport();

        yield* expectTag(
          loadProtocol({
            providers: [github(), github()],
            timeoutSeconds: 1,
            fetch: transport.fetch,
          }),
          "OpenIdClientConfigurationError",
        );
        yield* expectTag(
          loadProtocol({
            providers: [
              { ...github(), responseIssuerMode: "unsupported" },
              { ...google(), redirectUri: "https://app.test/auth/github/callback" },
            ],
            timeoutSeconds: 1,
            fetch: transport.fetch,
          }),
          "OpenIdClientConfigurationError",
        );
        expect(transport.requests).toHaveLength(0);
      }),
  );

  for (const claims of [
    { name: undefined },
    { email: "unverified@example.test", email_verified: false },
    { email: "member@example.test" },
  ]) {
    it.live(`does not require email or profile: ${JSON.stringify(claims)}`, () =>
      Effect.gen(function* () {
        const transport = makeTransport({ claims });

        const protocol = yield* loadProtocol({
          providers: [google()],
          timeoutSeconds: 1,
          fetch: transport.fetch,
        });

        const started = yield* begin(protocol, "google");

        transport.setNonce(started);
        const result = yield* exchange(protocol, started);

        expect(result.identity.subject).toBe("stable-google-sub");
        expect(result).not.toHaveProperty("email");
      }),
    );
  }

  for (const claims of [
    { iss: "https://other.test" },
    { aud: "wrong-client" },
    { nonce: "wrong-nonce" },
    { exp: 1 },
    { iat: 9999999999 },
  ]) {
    it.live(`rejects invalid OIDC claims: ${Object.keys(claims)[0]}`, () =>
      Effect.gen(function* () {
        const transport = makeTransport({ claims });

        const protocol = yield* loadProtocol({
          providers: [github(), google()],
          timeoutSeconds: 1,
          fetch: transport.fetch,
        });

        const started = yield* begin(protocol, "google");

        transport.setNonce(started);
        yield* expectTag(exchange(protocol, started), "OAuthProtocolRejected");
        expect(transport.requests.filter((request) => request.method === "POST")).toHaveLength(1);
      }),
    );
  }

  for (const [body, tag] of [
    [{ error: "bad_verification_code" }, "OAuthProtocolRejected"],
    [{ error: "bad_verification_code", access_token: "ambiguous" }, "OAuthUnavailable"],
    [{ access_token: "token", token_type: "bearer", scope: "repo" }, "OAuthUnavailable"],
  ] as const) {
    it.live(
      `keeps GitHub receipt compatibility inside the combined protocol: ${JSON.stringify(body)}`,
      () =>
        Effect.gen(function* () {
          const transport = makeTransport({ tokenResponse: () => json(body) });

          const protocol = yield* loadProtocol({
            providers: [github(), google()],
            timeoutSeconds: 1,
            fetch: transport.fetch,
          });

          yield* expectTag(exchange(protocol, yield* begin(protocol, "github")), tag);
          expect(transport.requests.filter((request) => request.method === "POST")).toHaveLength(1);
          expect(transport.requests.some((request) => request.url.endsWith("/user"))).toBe(false);
        }),
    );
  }

  it.live("the standalone GitHub constructor uses the same provider rules", () =>
    Effect.gen(function* () {
      const transport = makeTransport({
        tokenResponse: () => json({ error: "bad_verification_code" }),
      });

      const protocol = yield* loadGitHubProtocol({
        clientId: "github",
        clientSecret: Redacted.make("secret"),
        redirectUri: "https://app.test/auth/github/callback",
        fetch: transport.fetch,
      });

      yield* expectTag(
        exchange(protocol, yield* begin(protocol, "github")),
        "OAuthProtocolRejected",
      );
    }),
  );

  it.live("validates GitHub's RFC 9207 issuer before exchanging a callback code", () =>
    Effect.gen(function* () {
      const transport = makeTransport();

      const protocol = yield* loadGitHubProtocol({
        registrations: [
          {
            configurationGeneration: 1,
            issuance: "active",
            clientId: "github",
            clientSecret: Redacted.make("secret"),
            callbacks: github().callbacks,
          },
        ],
        timeoutSeconds: 1,
        fetch: transport.fetch,
      });

      const started = yield* begin(protocol, "github");

      // Use GitHub's published issuer to reproduce an issuer-bearing callback,
      // independently of the adapter's own configuration.
      const githubIssuer = OAuthIssuer.make("https://github.com/login/oauth");

      expect(started.configuration.issuer).toBe(githubIssuer);
      expect(started.configuration.responseIssuerMode).toBe("required");

      const input = {
        configuration: started.configuration,
        secrets: started.secrets,
        verificationStartedAt: yield* DateTime.now,
        response: {
          _tag: "Code" as const,
          state: started.secrets.state,
          code: Redacted.make("single-use-code"),
        },
      };

      for (const issuer of [undefined, OAuthIssuer.make("https://github.com")]) {
        yield* expectTag(
          protocol.exchangeVerifiedIdentity({
            ...input,
            response: { ...input.response, ...(issuer === undefined ? {} : { issuer }) },
          }),
          "OAuthProtocolRejected",
        );
      }
      expect(transport.requests).toHaveLength(0);
      expect(
        yield* protocol.exchangeVerifiedIdentity({
          ...input,
          response: { ...input.response, issuer: githubIssuer },
        }),
      ).toEqual({
        identity: { provider: "github", issuer: githubIssuer, subject: "42" },
        profile: {
          displayName: "octocat",
          handle: "octocat",
          email: "untrusted-profile@example.test",
          providerData: { id: 42, login: "octocat", email: "untrusted-profile@example.test" },
        },
      });
      expect(transport.requests.filter((request) => request.method === "POST")).toHaveLength(1);
    }),
  );

  it.live("an identity decoder defect fails unavailable without repeating the exchange", () =>
    Effect.gen(function* () {
      const transport = makeTransport();
      const provider = github();

      const protocol = yield* loadProtocol({
        providers: [
          {
            ...provider,
            identitySource: {
              ...provider.identitySource,
              decodeIdentity: () => Effect.die("private decoder detail"),
            },
          },
          google(),
        ],
        timeoutSeconds: 1,
        fetch: transport.fetch,
      });

      yield* expectTag(exchange(protocol, yield* begin(protocol, "github")), "OAuthUnavailable");
      expect(transport.requests.filter((request) => request.method === "POST")).toHaveLength(1);
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
          fetch: transport.fetch,
        });

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
