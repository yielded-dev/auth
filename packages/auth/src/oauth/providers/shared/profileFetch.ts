import type * as OAuth from "@yielded/oauth/OAuth";
import type * as OAuthError from "@yielded/oauth/OAuthError";
import * as Effect from "effect/Effect";
import type * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import type * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import { makeScopedOperation } from "../../../internal/scoped-operation";
import {
  Bearer,
  captureHardenedHttp,
  decode,
  Endpoint,
  endpointMatchesIssuer,
  freezePlainJson,
  Headers,
  invalidArgument,
  invalidResponse,
  Issuer,
  parseJsonResponse,
  RequestOptions,
  reveal,
  sendRequest,
  text,
  transportFailed,
} from "./http";

export interface ProfileFetchOptions {
  readonly issuer: string;
  readonly url: string;
  readonly method?: "GET" | "POST";
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly timeoutMs: number;
  readonly maxResponseBytes?: number;
}

export type ProfileFetcher = (
  accessToken: Redacted.Redacted<string>,
) => Effect.Effect<OAuth.JsonObject, OAuthError.OAuthError>;

const ProfileFetchOptionsSchema = Schema.Struct({
  issuer: Issuer,
  url: Endpoint,
  method: Schema.optionalKey(Schema.Literals(["GET", "POST"])),
  headers: Schema.optionalKey(Headers),
  body: Schema.optionalKey(text(4096)),
  ...RequestOptions.fields,
}).check(Schema.makeFilter((options) => endpointMatchesIssuer(options.issuer, options.url)));

/** Scoped, single-attempt plain-OAuth profile fetcher supporting GET/POST,
 * validated non-forbidden headers, and optional JSON POST bodies. */
export const makeProfileFetch = Effect.fnUntraced(function* (
  input: ProfileFetchOptions,
): Effect.fn.Return<ProfileFetcher, OAuthError.OAuthError, HttpClient.HttpClient | Scope.Scope> {
  const options = yield* decode(ProfileFetchOptionsSchema, input, () =>
    invalidArgument("Invalid OAuth profile fetch options"),
  );

  if ((options.method === undefined || options.method === "GET") && options.body !== undefined) {
    return yield* invalidArgument("GET profile requests cannot include a body");
  }

  const profile = freezePlainJson({
    url: new URL(options.url).href,
    method: options.method ?? ("GET" as const),
    ...(options.headers === undefined ? {} : { headers: { ...options.headers } }),
    ...(options.body === undefined ? {} : { body: options.body }),
  });

  const requestLimits = {
    timeoutMs: options.timeoutMs,
    maxResponseBytes: options.maxResponseBytes,
  };

  const http = yield* captureHardenedHttp;

  const run = yield* makeScopedOperation(() =>
    transportFailed("userinfo", "The owning scope is closed"),
  );

  return (accessToken: Redacted.Redacted<string>) =>
    run(
      Effect.gen(function* () {
        const token = yield* reveal(
          yield* decode(Bearer, accessToken, () => invalidArgument("Invalid bearer access token")),
        );

        let request = (
          profile.method === "POST"
            ? HttpClientRequest.post(profile.url)
            : HttpClientRequest.get(profile.url)
        ).pipe(
          HttpClientRequest.acceptJson,
          HttpClientRequest.setHeaders(profile.headers ?? {}),
          HttpClientRequest.setHeader("authorization", `Bearer ${token}`),
        );

        if (profile.method === "POST" && profile.body !== undefined) {
          request = HttpClientRequest.bodyText(request, profile.body, "application/json");
        }

        const response = yield* sendRequest(http, request, requestLimits, "userinfo");

        if (response.status !== 200) {
          return yield* invalidResponse(
            "userinfo",
            response.status,
            "Unexpected profile response status",
          );
        }

        const document = yield* parseJsonResponse(response, "userinfo");

        return yield* reveal(document.body, () =>
          invalidResponse("userinfo", response.status, "Profile response body is unavailable"),
        );
      }),
    );
});
