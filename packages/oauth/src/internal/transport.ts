import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import type * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as Tracer from "effect/Tracer";

import * as OAuthError from "../OAuthError.ts";
import * as V from "./validation.ts";

export interface Options {
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
}

const transportFailed = (
  endpoint: OAuthError.TransportFailed["endpoint"],
  description: string,
  options?: { readonly status?: number | undefined; readonly cause?: unknown },
): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.TransportFailed({
      endpoint,
      description,
      ...(options?.status === undefined ? {} : { status: options.status }),
      ...(options?.cause === undefined ? {} : { cause: options.cause }),
    }),
  });

/** Caller supplies a nonretrying, nonredirecting HttpClient. Each body and socket
 * belongs to this request's Scope; cancellation reaches the entire body read. */
export const request = Effect.fnUntraced(
  function* (
    client: HttpClient.HttpClient,
    request: HttpClientRequest.HttpClientRequest,
    options: Options,
    endpoint: OAuthError.TransportFailed["endpoint"],
  ) {
    const response = yield* HttpClient.withScope(client).execute(request);

    if (response.url !== request.url || (response.status >= 300 && response.status < 400))
      return yield* transportFailed(
        endpoint,
        "Redirects and unexpected response URLs are not allowed",
        {
          status: response.status,
        },
      );
    const announced = response.headers["content-length"];

    if (
      announced !== undefined &&
      (!/^\d+$/u.test(announced) || Number(announced) > options.maxResponseBytes)
    )
      return yield* transportFailed(endpoint, "Response body exceeds maximum allowed size", {
        status: response.status,
      });
    const buffer = new Uint8Array(options.maxResponseBytes);

    const length = yield* Stream.runFoldEffect(
      response.stream,
      () => 0,
      (length, chunk) => {
        if (chunk.byteLength > buffer.length - length)
          return Effect.fail(
            transportFailed(endpoint, "Response body exceeds maximum allowed size", {
              status: response.status,
            }),
          );
        buffer.set(chunk, length);

        return Effect.succeed(length + chunk.byteLength);
      },
    ).pipe(
      Effect.catchCauseIf(
        (cause) =>
          cause.reasons.length > 0 &&
          cause.reasons.every(
            (reason) =>
              Cause.isFailReason(reason) &&
              reason.error._tag === "HttpClientError" &&
              reason.error.reason._tag === "EmptyBodyError",
          ),
        () => Effect.succeed(0),
      ),
    );

    return {
      status: response.status,
      contentType: response.headers["content-type"] ?? null,
      bytes: Redacted.make(buffer.subarray(0, length)),
    };
  },
  (effect, _client, _request, options, endpoint) =>
    Effect.suspend(() => {
      let failure: Cause.Cause<OAuthError.OAuthError> | undefined;

      return effect.pipe(
        Effect.scoped,
        Effect.provideService(FetchHttpClient.RequestInit, {
          // Workers supports manual redirects; the status check above rejects them.
          redirect: "manual",
          credentials: "omit",
          cache: "no-store",
        }),
        Effect.provideService(Tracer.DisablePropagation, true),
        Effect.catchCause((cause) =>
          Effect.failCause(
            Cause.map(cause, (error) =>
              OAuthError.isOAuthError(error)
                ? error
                : transportFailed(endpoint, "HTTP transport request failed", { cause: error }),
            ),
          ),
        ),
        // timeoutOrElse joins its loser but discards that Exit. Retain cleanup
        // failures before the race, including when the caller cancels the race.
        Effect.onExit((exit) =>
          Effect.sync(() => {
            if (Exit.isFailure(exit) && !Cause.hasInterruptsOnly(exit.cause)) failure = exit.cause;
          }),
        ),
        Effect.timeoutOrElse({
          duration: options.timeoutMs,
          orElse: () => {
            const timeout = transportFailed(endpoint, "HTTP request timed out");

            return Effect.failCause(
              failure === undefined
                ? Cause.fail(timeout)
                : Cause.combine(Cause.fail(timeout), failure),
            );
          },
        }),
        Effect.onInterrupt(() => (failure === undefined ? Effect.void : Effect.failCause(failure))),
      );
    }),
);

export const isJson = (contentType: string | null) =>
  contentType?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";

const jsonError = (
  endpoint: OAuthError.TransportFailed["endpoint"],
  status: number,
  description: string,
): OAuthError.OAuthError =>
  endpoint === "discovery" || endpoint === "jwks"
    ? transportFailed(endpoint, description, { status })
    : new OAuthError.OAuthError({
        reason: new OAuthError.InvalidResponse({ endpoint, status, description }),
      });

export const json = Effect.fnUntraced(function* (
  response: Effect.Success<ReturnType<typeof request>>,
  endpoint: OAuthError.TransportFailed["endpoint"],
) {
  if (!isJson(response.contentType))
    return yield* jsonError(endpoint, response.status, "Expected application/json response");

  const bytes = yield* V.reveal(response.bytes, () =>
    jsonError(endpoint, response.status, "Response body is unavailable"),
  );

  const text = yield* Effect.try({
    try: () => new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    catch: () => jsonError(endpoint, response.status, "Response body is not valid UTF-8"),
  });

  const body = yield* V.decode(Json, text, () =>
    jsonError(endpoint, response.status, "Response body is not a bounded JSON object"),
  );

  return {
    status: response.status,
    contentType: response.contentType,
    body: Redacted.make(V.freeze(body)),
  };
});

const Json = Schema.fromJsonString(V.JsonObject);

/** Capture Fetch's optional reference at the installed-client boundary too. */
export const capture = Effect.gen(function* () {
  const client = yield* HttpClient.HttpClient;
  const fetch = yield* FetchHttpClient.Fetch;

  return HttpClient.transformResponse(client, (effect) =>
    effect.pipe(
      Effect.provideService(FetchHttpClient.Fetch, fetch),
      Effect.provideService(Tracer.DisablePropagation, true),
    ),
  );
});
