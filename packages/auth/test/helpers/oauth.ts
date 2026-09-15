import { AuthTokenCodec } from "@yielded/auth/AuthTokenCodec";
import { type AuthTokenError } from "@yielded/auth/Errors";
import { Effect, Layer } from "effect";
import { HttpClient, HttpClientResponse } from "effect/unstable/http";
import { expect } from "vite-plus/test";

import { OAuth } from "../../src/oauth/OAuth";
import { OAuthConnectionStore } from "../../src/oauth/OAuthConnectionStore";
import { type OAuthProvider } from "../../src/oauth/OAuthProvider";
import { OAuthProviders } from "../../src/oauth/OAuthProviders";
import { OAuthStateStore } from "../../src/oauth/OAuthStateStore";
import { layerCryptoDeterministic } from "../../src/testing/crypto";
import { layerKeyringTest } from "../../src/testing/keyring";

/** One request the stub `HttpClient` saw, with its body pre-parsed. */
export interface CapturedRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Record<string, string>;
  readonly form: URLSearchParams | undefined;
  readonly json: unknown;
}

export type StubResponder = (
  request: CapturedRequest,
) => { status?: number; body?: unknown } | undefined;

export interface OAuthTestHarness {
  readonly layer: Layer.Layer<OAuth, AuthTokenError>;
  readonly requests: Array<CapturedRequest>;
}

const bodyText = (body: unknown): string | undefined => {
  if (
    typeof body === "object" &&
    body !== null &&
    "_tag" in body &&
    body._tag === "Uint8Array" &&
    "body" in body &&
    body.body instanceof Uint8Array
  ) {
    return new TextDecoder().decode(body.body);
  }

  return undefined;
};

/**
 * The full OAuth stack over memory stores, a deterministic keyring/crypto,
 * and a scripted `HttpClient`: `respond` maps each captured request to a JSON
 * reply (default 404), and every request the workflow makes is recorded on
 * `requests` for assertions.
 */
export const makeOAuthHarness = (
  respond: StubResponder,
  providers: Iterable<OAuthProvider>,
): OAuthTestHarness => {
  const requests: Array<CapturedRequest> = [];

  const client = HttpClient.make((request, url) =>
    Effect.sync(() => {
      const text = bodyText(request.body);

      const contentType =
        typeof request.body === "object" && request.body !== null && "contentType" in request.body
          ? String(request.body.contentType)
          : "";

      const captured: CapturedRequest = {
        method: request.method,
        url: url.toString(),
        headers: { ...request.headers },
        form:
          text !== undefined && contentType.includes("application/x-www-form-urlencoded")
            ? new URLSearchParams(text)
            : undefined,
        json:
          text !== undefined && contentType.includes("application/json")
            ? JSON.parse(text)
            : undefined,
      };

      requests.push(captured);
      const reply = respond(captured) ?? { status: 404, body: {} };

      return HttpClientResponse.fromWeb(
        request,
        new Response(reply.body === undefined ? null : JSON.stringify(reply.body), {
          status: reply.status ?? 200,
          headers: { "content-type": "application/json" },
        }),
      );
    }),
  );

  const layer = OAuth.layer.pipe(
    Layer.provide(OAuthProviders.layer(providers)),
    Layer.provide(OAuthStateStore.layerMemory),
    Layer.provide(OAuthConnectionStore.layerMemory),
    Layer.provide(AuthTokenCodec.layerWebCrypto),
    Layer.provide(layerKeyringTest),
    Layer.provide(layerCryptoDeterministic()),
    Layer.provide(Layer.succeed(HttpClient.HttpClient)(client)),
  );

  return { layer, requests };
};

/** Asserts the effect fails with the given tagged error. */
export const expectTag = <A, E extends { readonly _tag: string }, R>(
  effect: Effect.Effect<A, E, R>,
  tag: E["_tag"],
) =>
  Effect.exit(effect).pipe(
    Effect.map((exit) => {
      expect(exit._tag).toBe("Failure");
      if (exit._tag === "Failure") {
        const tags = exit.cause.reasons.map((reason) =>
          reason._tag === "Fail" ? reason.error._tag : reason._tag,
        );

        expect(tags).toContain(tag);
      }
    }),
  );
