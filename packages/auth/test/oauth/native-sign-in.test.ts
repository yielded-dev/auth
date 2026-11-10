import { createHash, generateKeyPairSync } from "node:crypto";

import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { it } from "@effect/vitest";
import * as Apple from "@yielded/auth/Apple";
import {
  OAuthCallbackId,
  OAuthProviderKey,
  OAuthRedirectUri,
  type OAuthProtocol,
  type OAuthNativeProtocolPreparation,
} from "@yielded/auth/OAuth";
import { RequestBindingFlowId } from "@yielded/auth/Operations";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Jwt from "effect/jose/Jwt";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as TestClock from "effect/testing/TestClock";
import { describe, expect } from "vite-plus/test";

import { expectTag } from "./helpers/oauth";

// Human-requested seam: native (no-browser) Sign in with Apple through the real Apple
// provider, its discovery pinning and shared ID-token verifier. Only Apple's HTTP
// endpoints are substituted; the token endpoint must never be called.
// Failure inventory:
// 1. A platform ID token for any listed bundle ID, carrying the flow nonce, verifies
//    to one identity; the first-consent name fills the profile.
// 2. A token with another nonce, no nonce, or an unlisted audience is rejected.
// 3. A token carrying `c_hash` verifies only with its own authorization code.
// 4. Web and native registrations coexist, neither serves the other flow, and a
//    native registration needs no signing key or callback.

const seconds = 1_700_000_000;
const platform = Layer.mergeAll(FetchHttpClient.layer, NodeCrypto.layer);
const json = (body: unknown) => Response.json(body);
const apple = OAuthProviderKey.make("apple");
const iosApp = "com.example.ios";
const macApp = "com.example.mac";
const servicesId = "com.example.services";
const webCallback = OAuthRedirectUri.make("https://app.test/auth/apple/callback");

const IdToken = Schema.Struct({
  iss: Schema.String,
  sub: Schema.String,
  aud: Schema.String,
  iat: Schema.Finite,
  exp: Schema.Finite,
  nonce: Schema.optionalKey(Schema.String),
  c_hash: Schema.optionalKey(Schema.String),
  email: Schema.String,
});

const web = () => ({
  clientId: servicesId,
  teamId: "TEAM123456",
  keyId: "KEY1234567",
  privateKey: Redacted.make(
    generateKeyPairSync("ec", { namedCurve: "P-256" })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString(),
  ),
  scopes: ["openid", "email", "name"] as const,
});

const native = { kind: "native" as const, bundleIds: [iosApp, macApp] as const };

const codeHash = (code: string) =>
  createHash("sha256").update(code).digest().subarray(0, 16).toString("base64url");

const harness = Effect.fnUntraced(function* (
  kinds: ReadonlyArray<"web" | "native"> = ["web", "native"],
) {
  yield* TestClock.setTime(seconds * 1000);
  const pair = yield* Jwk.generateKeyPair({ algorithm: "RS256", kid: "apple" });
  const signing = yield* Jwk.importPrivate(pair.privateKey, "RS256");
  const tokenCalls: Array<string> = [];

  const fetch: typeof globalThis.fetch = async (input) => {
    const url = input instanceof Request ? input.url : String(input);

    if (url === "https://appleid.apple.com/.well-known/openid-configuration")
      return json({
        issuer: "https://appleid.apple.com",
        authorization_endpoint: "https://appleid.apple.com/auth/authorize",
        token_endpoint: "https://appleid.apple.com/auth/token",
        jwks_uri: "https://appleid.apple.com/auth/keys",
        response_types_supported: ["code"],
        response_modes_supported: ["query", "fragment", "form_post"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      });
    if (url === "https://appleid.apple.com/auth/keys") return json({ keys: [pair.publicKey] });
    tokenCalls.push(url);
    throw new Error(`Unexpected endpoint ${url}`);
  };

  const protocol = yield* Apple.provider({
    registrations: kinds.map((kind) => (kind === "native" ? native : web())),
  })
    .configure({
      provider: apple,
      // A native-only host mounts no browser callback.
      callbacks: kinds.includes("web")
        ? [{ callbackId: OAuthCallbackId.make("apple"), redirectUri: webCallback }]
        : [],
    })
    .pipe(Effect.provideService(FetchHttpClient.Fetch, fetch));

  const sign = (claims: {
    readonly sub?: string;
    readonly nonce?: string;
    readonly aud?: string;
    readonly code?: string;
  }) =>
    Jwt.sign(
      IdToken,
      {
        iss: "https://appleid.apple.com",
        sub: claims.sub ?? "apple-subject",
        aud: claims.aud ?? iosApp,
        iat: seconds,
        exp: seconds + 300,
        ...(claims.nonce === undefined ? {} : { nonce: claims.nonce }),
        ...(claims.code === undefined ? {} : { c_hash: codeHash(claims.code) }),
        email: "ada@privaterelay.appleid.com",
      },
      signing,
      { kid: "apple" },
    ).pipe(Effect.map(Redacted.value));

  return { protocol, tokenCalls, sign };
});

const verify = (
  protocol: OAuthProtocol["Service"],
  started: OAuthNativeProtocolPreparation,
  credential: {
    readonly idToken: string;
    readonly code?: string;
    readonly name?: { readonly givenName?: string; readonly familyName?: string };
  },
) => {
  if (protocol.verifyNativeIdentity === undefined) return Effect.die("missing native verifier");

  return protocol.verifyNativeIdentity({
    configuration: started.configuration,
    secrets: started.secrets,
    verificationStartedAt: DateTime.makeUnsafe(seconds * 1000),
    credential: {
      idToken: Redacted.make(credential.idToken),
      ...(credential.code === undefined ? {} : { code: Redacted.make(credential.code) }),
      ...(credential.name === undefined ? {} : { name: credential.name }),
    },
  });
};

const prepare = (protocol: OAuthProtocol["Service"], flowId: string) =>
  protocol.prepareNative === undefined
    ? Effect.die("missing native preparation")
    : protocol.prepareNative({ provider: apple, flowId: RequestBindingFlowId.make(flowId) });

const nonceOf = (started: OAuthNativeProtocolPreparation) => {
  const nonce = started.secrets.oidcNonce;

  if (nonce === undefined) throw new Error("expected a native nonce");

  return Redacted.value(nonce);
};

describe("native Sign in with Apple verification", () => {
  it.effect("verifies a platform token for every listed app without a token exchange", () =>
    Effect.gen(function* () {
      const { protocol, tokenCalls, sign } = yield* harness();
      const started = yield* prepare(protocol, "flow-native");
      const nonce = nonceOf(started);

      expect(started.configuration).toMatchObject({ callbackId: "native", protocol: "oidc" });
      expect(started.configuration).not.toHaveProperty("redirectUri");
      expect(started.secrets.pkceVerifier).toBeUndefined();

      const fromIos = yield* verify(protocol, started, {
        idToken: yield* sign({ nonce, code: "ios-code" }),
        code: "ios-code",
        name: { givenName: "Ada", familyName: "Lovelace" },
      });

      const fromMac = yield* verify(protocol, started, {
        idToken: yield* sign({ nonce, aud: macApp }),
      });

      expect(fromIos.identity).toEqual({
        provider: "apple",
        issuer: "https://appleid.apple.com",
        subject: "apple-subject",
      });
      expect(fromMac.identity).toEqual(fromIos.identity);
      expect(fromIos.profile?.displayName).toBe("Ada Lovelace");
      expect(tokenCalls).toEqual([]);
    }).pipe(Effect.provide(platform), Effect.scoped),
  );

  it.effect("rejects another nonce, a missing nonce, and an unlisted audience", () =>
    Effect.gen(function* () {
      const { protocol, sign } = yield* harness();
      const started = yield* prepare(protocol, "flow-mismatch");
      const nonce = nonceOf(started);

      yield* expectTag(
        verify(protocol, started, { idToken: yield* sign({ nonce: "B".repeat(43) }) }),
        "OAuthProtocolRejected",
      );
      yield* expectTag(
        verify(protocol, started, { idToken: yield* sign({}) }),
        "OAuthProtocolRejected",
      );
      yield* expectTag(
        verify(protocol, started, { idToken: yield* sign({ nonce, aud: servicesId }) }),
        "OAuthProtocolRejected",
      );
    }).pipe(Effect.provide(platform), Effect.scoped),
  );

  it.effect("requires the matching authorization code for a token's c_hash", () =>
    Effect.gen(function* () {
      const { protocol, sign } = yield* harness();
      const started = yield* prepare(protocol, "flow-code-hash");
      const idToken = yield* sign({ nonce: nonceOf(started), code: "platform-code" });

      yield* expectTag(verify(protocol, started, { idToken }), "OAuthProtocolRejected");
      yield* expectTag(
        verify(protocol, started, { idToken, code: "other-code" }),
        "OAuthProtocolRejected",
      );

      const verified = yield* verify(protocol, started, { idToken, code: "platform-code" });

      expect(verified.identity.subject).toBe("apple-subject");
    }).pipe(Effect.provide(platform), Effect.scoped),
  );

  it.effect("keeps web and native registrations separate", () =>
    Effect.gen(function* () {
      const both = yield* harness();

      const webFlow = yield* both.protocol.prepareAuthorization({
        provider: apple,
        flowId: RequestBindingFlowId.make("flow-web"),
      });

      expect(Redacted.value(webFlow.authorizationUrl)).toContain(`client_id=${servicesId}`);
      expect(webFlow.configuration.redirectUri).toBe(webCallback);

      const webOnly = yield* harness(["web"]);

      yield* expectTag(prepare(webOnly.protocol, "flow-web-only"), "OAuthRejected");

      const nativeOnly = yield* harness(["native"]);

      yield* expectTag(
        nativeOnly.protocol.prepareAuthorization({
          provider: apple,
          flowId: RequestBindingFlowId.make("flow-native-only"),
        }),
        "OAuthRejected",
      );
      // A native flow cannot be completed through the web exchange.
      const started = yield* prepare(nativeOnly.protocol, "flow-native-as-web");

      yield* expectTag(
        nativeOnly.protocol.exchangeVerifiedIdentity({
          configuration: { ...started.configuration, redirectUri: webCallback },
          secrets: started.secrets,
          verificationStartedAt: DateTime.makeUnsafe(seconds * 1000),
          response: {
            _tag: "Code",
            state: started.secrets.state,
            code: Redacted.make("platform-code"),
          },
        }),
        "OAuthUnavailable",
      );
      expect(nativeOnly.tokenCalls).toEqual([]);
    }).pipe(Effect.provide(platform), Effect.scoped),
  );
});
