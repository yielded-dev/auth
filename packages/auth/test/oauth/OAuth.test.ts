import { it as effectIt } from "@effect/vitest";
import { SubjectId } from "@yielded/auth/Schema";
import { Duration, Effect, Option, Redacted, Schema } from "effect";
import { TestClock } from "effect/testing";
import { HttpClientRequest } from "effect/unstable/http";
import { describe, expect } from "vite-plus/test";

import { OAuthProviderError } from "../../src/oauth/errors";
import { OAuth } from "../../src/oauth/OAuth";
import { type OAuthProvider, decodeStandardTokenGrant } from "../../src/oauth/OAuthProvider";
import { OAuthIdentity, OAuthProviderKey } from "../../src/oauth/schema";
import { type CapturedRequest, expectTag, makeOAuthHarness } from "../helpers/oauth";

// Provider-independent flow behavior through the public OAuth seam: state
// binding and single use, expiry, callback validation, refresh, and
// disconnection — driven by a fake provider and a scripted HttpClient, so the
// checks hold for every provider layer.

const fakeKey = Schema.decodeSync(OAuthProviderKey)("fake");
const missingKey = Schema.decodeSync(OAuthProviderKey)("missing");
const subjectA = Schema.decodeSync(SubjectId)("subject-a");
const subjectB = Schema.decodeSync(SubjectId)("subject-b");
const redirectUri = "https://app.test/oauth/fake/callback";

const FakeIdentityPayload = Schema.Struct({
  account_id: Schema.NonEmptyString,
  username: Schema.NonEmptyString,
});

// oxlint-disable-next-line no-restricted-properties -- Test double for the untrusted identity boundary.
const decodeFakeIdentityPayload = Schema.decodeUnknownEffect(FakeIdentityPayload);

const fakeProvider: OAuthProvider = {
  key: fakeKey,
  displayName: "Fake",
  clientId: "fake-client-id",
  clientSecret: Redacted.make("fake-client-secret"),
  endpoints: {
    authorization: "https://provider.test/oauth/authorize",
    token: "https://provider.test/oauth/token",
  },
  scopes: ["profile"],
  authorizationParams: {},
  decodeTokenGrant: decodeStandardTokenGrant(fakeKey),
  identity: {
    url: "https://provider.test/user",
    headers: {},
    decode: (payload) =>
      decodeFakeIdentityPayload(payload).pipe(
        Effect.mapBoth({
          onSuccess: (user) =>
            OAuthIdentity.make({
              provider: fakeKey,
              providerAccountId: user.account_id,
              handle: Option.some(user.username),
            }),
          onFailure: () =>
            OAuthProviderError.make({ provider: fakeKey, message: "Unrecognized identity" }),
        }),
      ),
  },
  revocation: Option.some((accessToken) =>
    HttpClientRequest.delete("https://provider.test/revoke").pipe(
      HttpClientRequest.bodyJsonUnsafe({ access_token: Redacted.value(accessToken) }),
    ),
  ),
};

const makeHarness = (
  respond: (request: CapturedRequest) => { status?: number; body?: unknown } | undefined,
) => makeOAuthHarness(respond, [fakeProvider]);

/** Token endpoint issuing an expiring access token plus a refresh token. */
const standardResponses = (request: CapturedRequest) => {
  if (request.url === "https://provider.test/oauth/token") {
    const grantType = request.form?.get("grant_type");

    if (grantType === "authorization_code" && request.form?.get("code") === "code-no-refresh") {
      return { body: { access_token: "access-plain", token_type: "bearer", expires_in: 3600 } };
    }
    if (grantType === "authorization_code") {
      return {
        body: {
          access_token: "access-1",
          token_type: "bearer",
          expires_in: 3600,
          refresh_token: "refresh-1",
          refresh_token_expires_in: 15_552_000,
        },
      };
    }
    if (grantType === "refresh_token" && request.form?.get("refresh_token") === "refresh-1") {
      return {
        body: {
          access_token: "access-2",
          token_type: "bearer",
          expires_in: 3600,
        },
      };
    }

    return { body: { error: "unsupported_grant_type" } };
  }
  if (request.url === "https://provider.test/user") {
    return { body: { account_id: "acct-1", username: "octo" } };
  }

  return undefined;
};

const beginAndCallback = Effect.fn("beginAndCallback")(function* (code = "code-1") {
  const oauth = yield* OAuth;

  const authorization = yield* oauth.begin({
    provider: fakeKey,
    subjectId: subjectA,
    redirectUri,
  });

  const state = new URL(authorization.url).searchParams.get("state") ?? "";

  return { oauth, authorization, state, params: { code, state } };
});

describe("OAuth flow", () => {
  effectIt.effect("begin issues a bound state and complete links the connection", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, authorization, state, params } = yield* beginAndCallback();
      const url = new URL(authorization.url);

      expect(url.origin + url.pathname).toBe("https://provider.test/oauth/authorize");
      expect(url.searchParams.get("client_id")).toBe("fake-client-id");
      expect(url.searchParams.get("redirect_uri")).toBe(redirectUri);
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("scope")).toBe("profile");
      expect(state.length).toBeGreaterThanOrEqual(32);

      const connection = yield* oauth.complete({
        provider: fakeKey,
        subjectId: subjectA,
        redirectUri,
        params,
      });

      expect(connection.identity.providerAccountId).toBe("acct-1");
      expect(Option.getOrUndefined(connection.identity.handle)).toBe("octo");
      expect(Redacted.value(connection.tokens.accessToken)).toBe("access-1");

      const exchange = harness.requests.find((request) => request.url.includes("/oauth/token"));

      expect(exchange?.method).toBe("POST");
      expect(exchange?.form?.get("grant_type")).toBe("authorization_code");
      expect(exchange?.form?.get("code")).toBe("code-1");
      expect(exchange?.form?.get("redirect_uri")).toBe(redirectUri);
      expect(exchange?.form?.get("client_id")).toBe("fake-client-id");
      expect(exchange?.form?.get("client_secret")).toBe("fake-client-secret");

      const token = yield* oauth.accessToken(fakeKey, subjectA);

      expect(Redacted.value(token)).toBe("access-1");
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("a callback state cannot be replayed", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params });
      yield* expectTag(
        oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params }),
        "InvalidOAuthState",
      );
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("an expired state is rejected", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* TestClock.adjust(Duration.minutes(10));
      yield* expectTag(
        oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params }),
        "InvalidOAuthState",
      );
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("the state is bound to the initiating subject", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* expectTag(
        oauth.complete({ provider: fakeKey, subjectId: subjectB, redirectUri, params }),
        "InvalidOAuthState",
      );
      // The mismatched attempt burned the state: the right subject cannot
      // complete with it either.
      yield* expectTag(
        oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params }),
        "InvalidOAuthState",
      );
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("the state is bound to the redirect URI", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* expectTag(
        oauth.complete({
          provider: fakeKey,
          subjectId: subjectA,
          redirectUri: "https://evil.test/callback",
          params,
        }),
        "InvalidOAuthState",
      );
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("a forged state is rejected without contacting the provider", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const oauth = yield* OAuth;

      yield* expectTag(
        oauth.complete({
          provider: fakeKey,
          subjectId: subjectA,
          redirectUri,
          params: { code: "code-1", state: "forged-state" },
        }),
        "InvalidOAuthState",
      );
      expect(harness.requests).toHaveLength(0);
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("a denied consent maps to OAuthAccessDenied and burns the state", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, state } = yield* beginAndCallback();

      yield* expectTag(
        oauth.complete({
          provider: fakeKey,
          subjectId: subjectA,
          redirectUri,
          params: { state, error: "access_denied" },
        }),
        "OAuthAccessDenied",
      );
      yield* expectTag(
        oauth.complete({
          provider: fakeKey,
          subjectId: subjectA,
          redirectUri,
          params: { state, code: "code-1" },
        }),
        "InvalidOAuthState",
      );
      expect(harness.requests).toHaveLength(0);
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("accessToken refreshes an expired token and persists the rotation", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params });
      yield* TestClock.adjust(Duration.hours(2));
      const token = yield* oauth.accessToken(fakeKey, subjectA);

      expect(Redacted.value(token)).toBe("access-2");

      const refresh = harness.requests.find(
        (request) => request.form?.get("grant_type") === "refresh_token",
      );

      expect(refresh?.form?.get("refresh_token")).toBe("refresh-1");

      // The refresh response carried no rotated refresh token, so the
      // previous one is retained on the stored connection.
      const connection = yield* oauth.connection(fakeKey, subjectA);

      expect(Option.isSome(connection)).toBe(true);
      if (Option.isSome(connection)) {
        expect(Redacted.value(connection.value.tokens.accessToken)).toBe("access-2");
        const refreshToken = Option.getOrUndefined(connection.value.tokens.refreshToken);

        expect(refreshToken !== undefined && Redacted.value(refreshToken)).toBe("refresh-1");
      }
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("an expired token without a refresh token requires reauthorization", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback("code-no-refresh");

      yield* oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params });
      yield* TestClock.adjust(Duration.hours(2));
      yield* expectTag(oauth.accessToken(fakeKey, subjectA), "OAuthReauthorizationRequired");
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("a rejected refresh grant requires reauthorization", () => {
    const harness = makeHarness((request) => {
      if (request.form?.get("grant_type") === "refresh_token") {
        return { body: { error: "invalid_grant" } };
      }

      return standardResponses(request);
    });

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params });
      yield* TestClock.adjust(Duration.hours(2));
      yield* expectTag(oauth.accessToken(fakeKey, subjectA), "OAuthReauthorizationRequired");
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("a rejected code exchange never stores a connection", () => {
    const harness = makeHarness((request) => {
      if (request.url === "https://provider.test/oauth/token") {
        return { body: { error: "bad_verification_code" } };
      }

      return standardResponses(request);
    });

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* expectTag(
        oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params }),
        "OAuthProviderError",
      );
      const connection = yield* oauth.connection(fakeKey, subjectA);

      expect(Option.isNone(connection)).toBe(true);
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("an unknown provider is a typed error", () => {
    const harness = makeHarness(standardResponses);

    return Effect.gen(function* () {
      const oauth = yield* OAuth;

      yield* expectTag(
        oauth.begin({ provider: missingKey, subjectId: subjectA, redirectUri }),
        "UnknownOAuthProvider",
      );
    }).pipe(Effect.provide(harness.layer));
  });

  effectIt.effect("disconnect removes the connection and is idempotent", () => {
    const harness = makeHarness((request) => {
      if (request.url === "https://provider.test/revoke") {
        return { status: 204 };
      }

      return standardResponses(request);
    });

    return Effect.gen(function* () {
      const { oauth, params } = yield* beginAndCallback();

      yield* oauth.complete({ provider: fakeKey, subjectId: subjectA, redirectUri, params });
      yield* oauth.disconnect(fakeKey, subjectA);
      yield* expectTag(oauth.accessToken(fakeKey, subjectA), "OAuthConnectionNotFound");
      yield* oauth.disconnect(fakeKey, subjectA);
    }).pipe(Effect.provide(harness.layer));
  });
});
