import { it as effectIt } from "@effect/vitest";
import { SubjectId } from "@yielded/auth/Schema";
import { Duration, Effect, Option, Redacted, Schema } from "effect";
import { TestClock } from "effect/testing";
import { describe, expect } from "vite-plus/test";

import {
  githubOAuthProviderKey,
  makeGithubOAuthProvider,
} from "../../src/oauth/GithubOAuthProvider";
import { OAuth } from "../../src/oauth/OAuth";
import { type CapturedRequest, expectTag, makeOAuthHarness } from "../helpers/oauth";

// The thin GitHub mapping over the generic flow: authorization URL shape for
// a GitHub App (no scopes), the user-to-server token exchange including
// GitHub's 200-status error payloads, identity normalization preserving the
// numeric user id and login, refresh, and the revocation request shape.

const clientId = "Iv1.abcdef0123456789";
const clientSecret = Redacted.make("github-client-secret");
const subject = Schema.decodeSync(SubjectId)("actor-github");
const redirectUri = "https://app.test/oauth/github/callback";

const githubTokenResponse = {
  access_token: "ghu_user-access-token",
  expires_in: 28_800,
  refresh_token: "ghr_refresh-token",
  refresh_token_expires_in: 15_811_200,
  token_type: "bearer",
  scope: "",
};

const makeHarness = (
  respond: (request: CapturedRequest) => { status?: number; body?: unknown } | undefined,
) => makeOAuthHarness(respond, [makeGithubOAuthProvider({ clientId, clientSecret })]);

const githubResponses = (request: CapturedRequest) => {
  if (request.url === "https://github.com/login/oauth/access_token") {
    return { body: githubTokenResponse };
  }
  if (request.url === "https://api.github.com/user") {
    // GitHub returns many more fields; only id and login are contractual.
    return { body: { id: 583_231, login: "octocat", name: "The Octocat", type: "User" } };
  }
  if (request.url === `https://api.github.com/applications/${clientId}/token`) {
    return { status: 204 };
  }

  return undefined;
};

const linkGithub = Effect.fn("linkGithub")(function* () {
  const oauth = yield* OAuth;

  const authorization = yield* oauth.begin({
    provider: githubOAuthProviderKey,
    subjectId: subject,
    redirectUri,
  });

  const state = new URL(authorization.url).searchParams.get("state") ?? "";

  const connection = yield* oauth.complete({
    provider: githubOAuthProviderKey,
    subjectId: subject,
    redirectUri,
    params: { code: "gh-code", state },
  });

  return { oauth, authorization, connection };
});

describe("GitHub OAuth provider", () => {
  effectIt.effect("authorizes against the GitHub App endpoint without scopes", () => {
    const harness = makeHarness(githubResponses);

    return Effect.gen(function* () {
      const { authorization } = yield* linkGithub();
      const url = new URL(authorization.url);

      expect(url.origin + url.pathname).toBe("https://github.com/login/oauth/authorize");
      expect(url.searchParams.get("client_id")).toBe(clientId);
      expect(url.searchParams.get("redirect_uri")).toBe(redirectUri);
      // GitHub App user access tokens take their permissions from the app
      // installation; the OAuth-App scope parameter must not be sent.
      expect(url.searchParams.get("scope")).toBeNull();
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("exchanges the code and maps GitHub's token and identity payloads", () => {
    const harness = makeHarness(githubResponses);

    return Effect.gen(function* () {
      const { connection } = yield* linkGithub();

      expect(connection.identity.providerAccountId).toBe("583231");
      expect(Option.getOrUndefined(connection.identity.handle)).toBe("octocat");
      expect(Redacted.value(connection.tokens.accessToken)).toBe("ghu_user-access-token");
      expect(connection.tokens.tokenType).toBe("bearer");
      expect(Option.isSome(connection.tokens.accessTokenExpiresAt)).toBe(true);
      const refreshToken = Option.getOrUndefined(connection.tokens.refreshToken);

      expect(refreshToken !== undefined && Redacted.value(refreshToken)).toBe("ghr_refresh-token");

      const exchange = harness.requests.find(
        (request) => request.url === "https://github.com/login/oauth/access_token",
      );

      expect(exchange?.method).toBe("POST");
      expect(exchange?.headers.accept).toBe("application/json");
      expect(exchange?.form?.get("grant_type")).toBe("authorization_code");
      expect(exchange?.form?.get("code")).toBe("gh-code");
      expect(exchange?.form?.get("client_id")).toBe(clientId);
      expect(exchange?.form?.get("client_secret")).toBe("github-client-secret");

      const identity = harness.requests.find(
        (request) => request.url === "https://api.github.com/user",
      );

      expect(identity?.headers.authorization).toBe("Bearer ghu_user-access-token");
      expect(identity?.headers["x-github-api-version"]).toBe("2022-11-28");
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("maps GitHub's 200-status error payload to a typed failure", () => {
    const harness = makeHarness((request) => {
      if (request.url === "https://github.com/login/oauth/access_token") {
        return {
          body: {
            error: "bad_verification_code",
            error_description: "The code passed is incorrect or expired.",
          },
        };
      }

      return githubResponses(request);
    });

    return Effect.gen(function* () {
      const oauth = yield* OAuth;

      const authorization = yield* oauth.begin({
        provider: githubOAuthProviderKey,
        subjectId: subject,
        redirectUri,
      });

      const state = new URL(authorization.url).searchParams.get("state") ?? "";

      yield* expectTag(
        oauth.complete({
          provider: githubOAuthProviderKey,
          subjectId: subject,
          redirectUri,
          params: { code: "stale-code", state },
        }),
        "OAuthProviderError",
      );
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("rejects an identity payload without the numeric user id", () => {
    const harness = makeHarness((request) => {
      if (request.url === "https://api.github.com/user") {
        return { body: { id: "not-a-number", login: "octocat" } };
      }

      return githubResponses(request);
    });

    return expectTag(linkGithub(), "OAuthProviderError").pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("refreshes an expired user access token through the same endpoint", () => {
    const harness = makeHarness((request) => {
      if (
        request.url === "https://github.com/login/oauth/access_token" &&
        request.form?.get("grant_type") === "refresh_token"
      ) {
        return {
          body: {
            ...githubTokenResponse,
            access_token: "ghu_rotated-access-token",
            refresh_token: "ghr_rotated-refresh-token",
          },
        };
      }

      return githubResponses(request);
    });

    return Effect.gen(function* () {
      const { oauth } = yield* linkGithub();

      yield* TestClock.adjust(Duration.hours(9));
      const token = yield* oauth.accessToken(githubOAuthProviderKey, subject);

      expect(Redacted.value(token)).toBe("ghu_rotated-access-token");

      const refresh = harness.requests.find(
        (request) => request.form?.get("grant_type") === "refresh_token",
      );

      expect(refresh?.url).toBe("https://github.com/login/oauth/access_token");
      expect(refresh?.form?.get("refresh_token")).toBe("ghr_refresh-token");
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("disconnect revokes the user access token via the applications API", () => {
    const harness = makeHarness(githubResponses);

    return Effect.gen(function* () {
      const { oauth } = yield* linkGithub();

      yield* oauth.disconnect(githubOAuthProviderKey, subject);

      const revocation = harness.requests.find(
        (request) => request.url === `https://api.github.com/applications/${clientId}/token`,
      );

      expect(revocation?.method).toBe("DELETE");
      expect(revocation?.headers.authorization).toBe(
        `Basic ${btoa(`${clientId}:github-client-secret`)}`,
      );
      expect(revocation?.json).toEqual({ access_token: "ghu_user-access-token" });

      const connection = yield* oauth.connection(githubOAuthProviderKey, subject);

      expect(Option.isNone(connection)).toBe(true);
    }).pipe(Effect.provide(harness.layer));
  });
});
