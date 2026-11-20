import * as ClientAuth from "@yielded/oauth/ClientAuth";
import * as Grant from "@yielded/oauth/Grant";
import * as OAuth from "@yielded/oauth/OAuth";
import * as OAuthError from "@yielded/oauth/OAuthError";
import * as Cause from "effect/Cause";
import type * as Digest from "effect/crypto/Digest";
import type * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";
import * as Stream from "effect/Stream";
import * as Tracer from "effect/Tracer";

import { makeScopedOperation } from "../../../internal/scoped-operation";
import { timeoutOrElseWithCause } from "../../../internal/timeout";

const defaultMaxResponseBytes = 1_048_576;
const maxTokenRequestBytes = 131_072;
const maxAuthorizationUrlLength = 16_384;

const utf8Encoder = new TextEncoder();

export const invalidArgument = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.InvalidArgument({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

export const transportFailed = (
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

export const invalidResponse = (
  endpoint: OAuthError.InvalidResponse["endpoint"],
  status: number,
  description: string,
): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.InvalidResponse({ endpoint, status, description }),
  });

const sanitizeTransportCause = (error: unknown): unknown => {
  if (
    Predicate.isObject(error) &&
    (error as { readonly _tag?: unknown })._tag === "HttpClientError"
  ) {
    const reason = (error as { readonly reason?: unknown }).reason;

    const reasonTag =
      Predicate.isObject(reason) && typeof (reason as { readonly _tag?: unknown })._tag === "string"
        ? (reason as { readonly _tag: string })._tag
        : undefined;

    return reasonTag === undefined
      ? { _tag: "HttpClientError" }
      : { _tag: "HttpClientError", reason: reasonTag };
  }

  return undefined;
};

// Mirror of `@yielded/oauth` `internal/validation.ts` bounds and schemas used
// by plain-OAuth profile fetches and JSON token-body requests; keep in sync.
export const text = (maximum: number) => Schema.NonEmptyString.check(Schema.isMaxLength(maximum));

const integer = (minimum: number, maximum: number) =>
  Schema.Int.check(Schema.isBetween({ minimum, maximum }));

const secret = (maximum: number) => Schema.Redacted(text(maximum), { disallowJsonEncode: true });

/** HTTPS, or HTTP on an exact loopback host for local development. */
const validUrl = (value: string): boolean => {
  try {
    const url = new URL(value);

    return (
      (url.protocol === "https:" ||
        (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) &&
      url.username === "" &&
      url.password === "" &&
      !value.includes("#") &&
      // oxlint-disable-next-line no-control-regex -- Reject URL parser normalization of untrusted controls.
      !/[\s\\\u0000-\u001f\u007f]/u.test(value)
    );
  } catch {
    return false;
  }
};

export const Endpoint = text(2048).check(Schema.makeFilter(validUrl));

/** HTTP loopback endpoints require an HTTP loopback issuer. Remote issuers
 * cannot downgrade endpoints to HTTP. */
export const endpointMatchesIssuer = (issuer: string, endpoint: string): boolean =>
  new URL(endpoint).protocol === "https:" || new URL(issuer).protocol === "http:";

export const Issuer = Endpoint.check(
  Schema.makeFilter(
    (value) => !value.includes("?") && !new URL(value).pathname.includes("/.well-known/"),
  ),
);

const Callback = text(2048).check(
  Schema.makeFilter(
    (value) => validUrl(value) && new URL(value).href === value && !value.includes("?"),
  ),
);

// oxlint-disable-next-line no-control-regex -- RFC6749 scope-token permits these visible ASCII ranges.
const ScopeName = Schema.String.check(Schema.isPattern(/^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/));

const Scopes = Schema.Array(ScopeName).check(
  Schema.isMaxLength(64),
  Schema.makeFilter((values) => new Set(values).size === values.length),
);

const Resource = text(2048).check(
  Schema.makeFilter((value) => {
    try {
      const url = new URL(value);

      return (
        // oxlint-disable-next-line no-control-regex -- Preserve exact resource identifiers.
        url.username === "" && url.password === "" && !/[\s\\#\u0000-\u001f\u007f]/u.test(value)
      );
    } catch {
      return false;
    }
  }),
);

const Resources = Schema.Array(Resource).check(Schema.isMaxLength(64));

const Verifier = Schema.Redacted(
  Schema.String.check(Schema.isPattern(/^[A-Za-z0-9._~-]{43,128}$/)),
  { disallowJsonEncode: true },
);

export const Bearer = Schema.Redacted(
  text(16384).check(Schema.isPattern(/^[A-Za-z0-9._~+/-]+=*$/u)),
  { disallowJsonEncode: true },
);

export const RequestOptions = Schema.Struct({
  timeoutMs: Schema.Finite.check(Schema.isBetween({ minimum: 1, maximum: 60000 })),
  maxResponseBytes: integer(1, defaultMaxResponseBytes).pipe(
    Schema.withDecodingDefaultKey(Effect.succeed(defaultMaxResponseBytes)),
  ),
});

const reservedEndpointQueryParameters: ReadonlySet<string> = new Set([
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
  "redirect_uri",
  "response_type",
  "response_mode",
  "state",
  "code",
  "code_verifier",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "scope",
  "iss",
  "grant_type",
  "refresh_token",
  "token",
  "token_type_hint",
  "max_age",
  "request",
  "request_uri",
  "authorization_details",
  "id_token_hint",
  "login_hint",
  "login_hint_token",
  "subject_token",
  "subject_token_type",
  "actor_token",
  "actor_token_type",
  "requested_token_type",
]);

const reservedBodyParameters: ReadonlySet<string> = new Set([
  ...reservedEndpointQueryParameters,
  "resource",
]);

const Parameters = Schema.Record(
  Schema.String.check(Schema.isPattern(/^[A-Za-z][A-Za-z0-9._~-]{0,63}$/)),
  Schema.String.check(Schema.isMaxLength(2048)),
).check(
  Schema.makeFilter(
    (value) =>
      Object.keys(value).length <= 16 &&
      Object.keys(value).every((key) => !reservedBodyParameters.has(key.toLowerCase())),
  ),
);

const ProtocolEndpoint = Endpoint.check(
  Schema.makeFilter((value) =>
    Array.from(new URL(value).searchParams.keys()).every(
      (key) => !reservedEndpointQueryParameters.has(key.toLowerCase()),
    ),
  ),
);

const forbiddenHeaders: ReadonlySet<string> = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "host",
  "content-length",
  "content-type",
  "transfer-encoding",
  "connection",
  "upgrade",
  "trailer",
  "te",
  "traceparent",
  "tracestate",
  "baggage",
]);

const headerNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;

export const Headers = Schema.Record(
  Schema.String.check(Schema.isPattern(headerNamePattern)),
  Schema.String.check(Schema.isMaxLength(2048)),
).check(
  Schema.makeFilter((value) => {
    const names = Object.keys(value).map((name) => name.toLowerCase());

    return (
      names.length <= 16 &&
      new Set(names).size === names.length &&
      names.every((name) => !forbiddenHeaders.has(name)) &&
      Object.values(value).every((headerValue) => !/[\r\n]/u.test(headerValue))
    );
  }),
);

export const decode = <S extends Schema.Constraint>(
  schema: S,
  input: unknown,
  onError: () => OAuthError.OAuthError = () => invalidArgument("Invalid OAuth input"),
) =>
  Effect.suspend(() => Schema.decodeUnknownEffect(schema)(input, { reportInput: false })).pipe(
    Effect.mapError(onError),
    Effect.catchDefect(() => Effect.fail(onError())),
  );

export const reveal = <A>(
  value: Redacted.Redacted<A>,
  onError: () => OAuthError.OAuthError = () =>
    invalidArgument("Redacted OAuth value is unavailable"),
) => Effect.try({ try: () => Redacted.value(value), catch: onError });

/** Iteratively freeze freshly parsed wire JSON or owned configuration snapshots
 * without copying properties. */
export const freezePlainJson = <A>(value: A): A => {
  const pending: Array<unknown> = [value];
  const seen = new WeakSet<object>();

  while (pending.length > 0) {
    const item = pending.pop();

    if (!Predicate.isObjectOrArray(item) || Redacted.isRedacted(item) || seen.has(item)) continue;
    seen.add(item);
    for (const child of Object.values(item)) pending.push(child);
    Object.freeze(item);
  }

  return value;
};

const isJsonContentType = (contentType: string | null): boolean =>
  contentType?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";

/** Capture `HttpClient` and optional `FetchHttpClient.Fetch` once with manual
 * redirects, omitted credentials, `no-store`, and disabled trace propagation. */
export const captureHardenedHttp = Effect.gen(function* () {
  const client = yield* HttpClient.HttpClient;
  const fetch = yield* FetchHttpClient.Fetch;

  return HttpClient.transformResponse(client, (effect) =>
    effect.pipe(
      Effect.provideService(FetchHttpClient.Fetch, fetch),
      Effect.provideService(FetchHttpClient.RequestInit, {
        redirect: "manual",
        credentials: "omit",
        cache: "no-store",
      }),
      Effect.provideService(Tracer.DisablePropagation, true),
    ),
  );
});

export interface HttpResponse {
  readonly status: number;
  readonly contentType: string | null;
  readonly bytes: Redacted.Redacted<Uint8Array>;
}

/** Mirror of `@yielded/oauth` `internal/transport.ts::request` for plain-OAuth
 * profile fetches and JSON token-body requests; keep in sync. Single-attempt
 * bounded HTTP request with manual redirect rejection, `response.url`
 * verification, `5xx` transport classification, `Scope`-owned byte folding,
 * and cause-preserving timeout. */
export const sendRequest = Effect.fnUntraced(
  function* (
    client: HttpClient.HttpClient,
    request: HttpClientRequest.HttpClientRequest,
    options: { readonly timeoutMs: number; readonly maxResponseBytes: number },
    endpoint: OAuthError.TransportFailed["endpoint"],
  ) {
    const response = yield* HttpClient.withScope(client).execute(request);

    if (response.url !== request.url || (response.status >= 300 && response.status < 400)) {
      return yield* transportFailed(
        endpoint,
        "Redirects and unexpected response URLs are not allowed",
        { status: response.status },
      );
    }

    if (response.status >= 500) {
      return yield* transportFailed(endpoint, "Upstream endpoint returned a server error", {
        status: response.status,
      });
    }

    const announced = response.headers["content-length"];

    if (
      announced !== undefined &&
      (!/^\d+$/u.test(announced) || Number(announced) > options.maxResponseBytes)
    ) {
      return yield* transportFailed(endpoint, "Response body exceeds maximum allowed size", {
        status: response.status,
      });
    }

    const buffer = new Uint8Array(options.maxResponseBytes);

    const length = yield* Stream.runFoldEffect(
      response.stream,
      () => 0,
      (offset, chunk) => {
        if (chunk.byteLength > buffer.length - offset) {
          return Effect.fail(
            transportFailed(endpoint, "Response body exceeds maximum allowed size", {
              status: response.status,
            }),
          );
        }
        buffer.set(chunk, offset);

        return Effect.succeed(offset + chunk.byteLength);
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
    effect.pipe(
      Effect.scoped,
      Effect.provideService(FetchHttpClient.RequestInit, {
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
              : transportFailed(endpoint, "HTTP transport request failed", {
                  cause: sanitizeTransportCause(error),
                }),
          ),
        ),
      ),
      timeoutOrElseWithCause({
        duration: options.timeoutMs,
        orElse: () => Effect.fail(transportFailed(endpoint, "HTTP request timed out")),
      }),
    ),
);

const JsonObjectFromString = Schema.fromJsonString(Grant.TokenReceiptFromJson.fields.body.from);

/** Decode bounded UTF-8 bytes into a frozen plain JSON object using
 * `@yielded/oauth`'s plain-JSON schema validation, independent of Content-Type. */
export const decodeJsonObjectBytes = Effect.fnUntraced(function* (
  bytes: Redacted.Redacted<Uint8Array>,
  status: number,
  endpoint: OAuthError.InvalidResponse["endpoint"],
): Effect.fn.Return<Readonly<Record<string, Schema.Json>>, OAuthError.OAuthError> {
  const raw = yield* reveal(bytes, () =>
    invalidResponse(endpoint, status, "Response body is unavailable"),
  );

  const decoded = yield* Effect.try({
    try: () => new TextDecoder("utf-8", { fatal: true }).decode(raw),
    catch: () => invalidResponse(endpoint, status, "Response body is not valid UTF-8"),
  });

  const body = yield* decode(JsonObjectFromString, decoded, () =>
    invalidResponse(endpoint, status, "Response body is not a bounded JSON object"),
  );

  return freezePlainJson(body);
});

/** Mirror of `@yielded/oauth` `internal/transport.ts::json` for plain-OAuth
 * profile fetches and JSON token-body requests; keep in sync. Reuses
 * `@yielded/oauth`'s plain-JSON schema validation. */
export const parseJsonResponse = Effect.fnUntraced(function* (
  response: HttpResponse,
  endpoint: OAuthError.InvalidResponse["endpoint"],
): Effect.fn.Return<Grant.TokenReceipt, OAuthError.OAuthError> {
  if (!isJsonContentType(response.contentType)) {
    return yield* invalidResponse(endpoint, response.status, "Expected application/json response");
  }

  const body = yield* decodeJsonObjectBytes(response.bytes, response.status, endpoint);

  return {
    status: response.status,
    contentType: response.contentType,
    body: Redacted.make(body),
  };
});

const rewriteUrlCommaScope = Effect.fnUntraced(function* (
  base: Redacted.Redacted<string>,
  scopes: ReadonlyArray<string>,
): Effect.fn.Return<Redacted.Redacted<string>, OAuthError.OAuthError> {
  const url = new URL(
    yield* reveal(base, () => invalidArgument("Authorization URL is unavailable")),
  );

  url.searchParams.set("scope", scopes.join(","));

  if (url.href.length > maxAuthorizationUrlLength) {
    return yield* invalidArgument("Authorization URL exceeds maximum length");
  }

  return Redacted.make(url.href);
});

/** Build an authorization URL whose `scope` query parameter is comma-delimited.
 * Validates individual `ScopeName` entries first so multi-scope lists whose
 * joined wire string exceeds 256 characters still succeed under the 16,384-char
 * final URL cap. */
export const authorizationUrlWithCommaScopes = Effect.fnUntraced(function* (
  client: OAuth.Client["Service"],
  input: OAuth.AuthorizationUrlOptions,
): Effect.fn.Return<Redacted.Redacted<string>, OAuthError.OAuthError> {
  const scopes = yield* decode(Scopes, input.scopes, () =>
    invalidArgument("Invalid authorization scopes"),
  );

  const first = scopes[0];

  if (first === undefined) return yield* client.authorizationUrl({ ...input, scopes: [] });

  // Reserve `scope`'s exact query-parameter slot before rewriting its value in place.
  const base = yield* client.authorizationUrl({ ...input, scopes: [first] });

  return yield* rewriteUrlCommaScope(base, scopes);
});

/** Run `OAuth.authorize` for a comma-scope provider, keeping the original
 * `scopes` array on `transaction.scopes` and serializing comma-delimited
 * `scope` only on the authorization URL under the 16,384-char cap. */
export const authorizeWithCommaScopes = Effect.fnUntraced(function* (
  options: OAuth.AuthorizeOptions,
): Effect.fn.Return<
  OAuth.Authorization,
  OAuthError.OAuthError,
  OAuth.Client | Digest.Digest | SecureRandom.SecureRandom
> {
  const scopes = yield* decode(Scopes, options.scopes, () =>
    invalidArgument("Invalid authorization scopes"),
  );

  const first = scopes[0];

  if (first === undefined) return yield* OAuth.authorize({ ...options, scopes: [] });

  const authorized = yield* OAuth.authorize({ ...options, scopes: [first] });
  const url = yield* rewriteUrlCommaScope(authorized.url, scopes);

  return {
    url,
    transaction: {
      ...authorized.transaction,
      scopes: [...scopes],
    },
  };
});

/** Construct a form-encoded `refresh_token` `Grant` with comma-delimited
 * `scope` for dispatch through `OAuth.Client.exchangeRaw`, validating each
 * individual `ScopeName` before joining so multi-scope lists exceeding 256
 * wire characters succeed under the 131,072-byte encoded body limit. */
export const commaScopeRefreshGrant = Effect.fnUntraced(function* (input: {
  readonly refreshToken: Redacted.Redacted<string>;
  readonly scopes?: ReadonlyArray<string>;
  readonly resources?: ReadonlyArray<string>;
  readonly parameters?: Readonly<Record<string, string>>;
}): Effect.fn.Return<Grant.Grant, OAuthError.OAuthError> {
  const value = yield* decode(RefreshGrantSchema, input, () =>
    invalidArgument("Invalid refresh token grant input"),
  );

  const params: Array<readonly [string, string | Redacted.Redacted<string>]> = [];

  for (const [key, item] of Object.entries(value.parameters ?? {})) {
    params.push([key, item]);
  }
  for (const resource of value.resources ?? []) {
    params.push(["resource", resource]);
  }
  params.push(["refresh_token", value.refreshToken]);
  if (value.scopes !== undefined && value.scopes.length > 0) {
    params.push(["scope", value.scopes.join(",")]);
  }

  return Grant.make("refresh_token", params);
});

const JsonTokenSenderOptionsSchema = Schema.Struct({
  issuer: Issuer,
  tokenEndpoint: ProtocolEndpoint,
  clientId: text(1024),
  ...RequestOptions.fields,
  scopeSeparator: Schema.optionalKey(Schema.Literals([" ", ","])),
}).check(
  Schema.makeFilter((options) => endpointMatchesIssuer(options.issuer, options.tokenEndpoint)),
);

const CodeGrantSchema = Schema.Struct({
  parameters: Schema.optionalKey(Parameters),
  resources: Schema.optionalKey(Resources),
  code: secret(16384),
  redirectUri: Callback,
  pkceVerifier: Schema.optionalKey(Verifier),
});

const RefreshGrantSchema = Schema.Struct({
  parameters: Schema.optionalKey(Parameters),
  resources: Schema.optionalKey(Resources),
  refreshToken: secret(16384),
  scopes: Schema.optionalKey(Scopes),
});

const JsonStringRecord = Schema.fromJsonString(Schema.Record(Schema.String, Schema.String));

const encodeJsonObject = Effect.fnUntraced(function* (
  entries: Iterable<readonly [string, string]>,
): Effect.fn.Return<string, OAuthError.OAuthError> {
  const target: Record<string, string> = Object.create(null);

  for (const [key, value] of entries) {
    if (Object.hasOwn(target, key)) {
      return yield* invalidArgument("JSON token request cannot contain repeated parameters");
    }
    Object.defineProperty(target, key, {
      value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }

  return yield* Schema.encodeEffect(JsonStringRecord)(target).pipe(
    Effect.mapError(() => invalidArgument("Could not encode JSON token request body")),
  );
});

const buildJsonTokenRequest = (
  url: string,
  issuer: string,
  clientId: string,
  clientAuth: ClientAuth.Method<never>,
  bodyEntries: ReadonlyArray<readonly [string, string]>,
): Effect.Effect<HttpClientRequest.HttpClientRequest, OAuthError.OAuthError> =>
  ClientAuth.withPreparedRequest(
    clientAuth,
    { clientId, endpoint: url, issuer },
    bodyEntries,
    Effect.fnUntraced(function* (prepared) {
      const encoded = yield* encodeJsonObject(prepared.parameters);

      if (utf8Encoder.encode(encoded).length > maxTokenRequestBytes) {
        return yield* invalidArgument("Encoded token request body exceeds maximum size");
      }

      let request = HttpClientRequest.post(url).pipe(HttpClientRequest.acceptJson);

      for (const [name, value] of Object.entries(prepared.headers)) {
        request = HttpClientRequest.setHeader(request, name, value);
      }

      return HttpClientRequest.bodyText(request, encoded, "application/json");
    }),
    { forbidGrantType: true },
  );

export interface JsonTokenCodeGrantInput {
  readonly code: Redacted.Redacted<string>;
  readonly redirectUri: string;
  readonly pkceVerifier?: Redacted.Redacted<string>;
  readonly resources?: ReadonlyArray<string>;
  readonly parameters?: Readonly<Record<string, string>>;
}

export interface JsonTokenRefreshGrantInput {
  readonly refreshToken: Redacted.Redacted<string>;
  readonly scopes?: ReadonlyArray<string>;
  readonly resources?: ReadonlyArray<string>;
  readonly parameters?: Readonly<Record<string, string>>;
}

export interface JsonTokenSenderOptions {
  readonly issuer: string;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly clientAuth: ClientAuth.Method<never>;
  readonly timeoutMs: number;
  readonly maxResponseBytes?: number;
  readonly scopeSeparator?: " " | ",";
}

export interface JsonTokenSender {
  readonly codeGrant: (
    input: JsonTokenCodeGrantInput,
  ) => Effect.Effect<Grant.TokenReceipt, OAuthError.OAuthError>;
  readonly refreshGrant: (
    input: JsonTokenRefreshGrantInput,
  ) => Effect.Effect<Grant.TokenReceipt, OAuthError.OAuthError>;
}

/** Scoped, single-attempt JSON token endpoint sender (for providers such as
 * Notion that require `application/json` token requests) delegating client
 * authentication to `ClientAuth.Method`. */
export const makeJsonTokenSender = Effect.fnUntraced(function* (
  input: JsonTokenSenderOptions,
): Effect.fn.Return<JsonTokenSender, OAuthError.OAuthError, HttpClient.HttpClient | Scope.Scope> {
  const options = yield* decode(JsonTokenSenderOptionsSchema, input, () =>
    invalidArgument("Invalid OAuth JSON token sender options"),
  );

  const tokenUrl = new URL(options.tokenEndpoint).href;
  const scopeSeparator = options.scopeSeparator === "," ? "," : " ";
  const clientAuth = input.clientAuth;
  const http = yield* captureHardenedHttp;

  const run = yield* makeScopedOperation(() =>
    transportFailed("token", "The owning scope is closed"),
  );

  const dispatch = Effect.fnUntraced(function* (entries: ReadonlyArray<readonly [string, string]>) {
    const request = yield* buildJsonTokenRequest(
      tokenUrl,
      options.issuer,
      options.clientId,
      clientAuth,
      entries,
    );

    const response = yield* sendRequest(http, request, options, "token");

    return yield* parseJsonResponse(response, "token");
  });

  const codeGrant = (grantInput: JsonTokenCodeGrantInput) =>
    run(
      Effect.gen(function* () {
        const value = yield* decode(CodeGrantSchema, grantInput, () =>
          invalidArgument("Invalid authorization code grant input"),
        );

        const entries: Array<readonly [string, string]> = [];

        for (const [key, item] of Object.entries(value.parameters ?? {})) {
          entries.push([key, item]);
        }
        for (const resource of value.resources ?? []) {
          entries.push(["resource", resource]);
        }
        entries.push(["grant_type", "authorization_code"]);
        entries.push(["code", yield* reveal(value.code)]);
        if (value.pkceVerifier !== undefined) {
          entries.push(["code_verifier", yield* reveal(value.pkceVerifier)]);
        }
        entries.push(["redirect_uri", value.redirectUri]);

        return yield* dispatch(entries);
      }),
    );

  const refreshGrant = (grantInput: JsonTokenRefreshGrantInput) =>
    run(
      Effect.gen(function* () {
        const value = yield* decode(RefreshGrantSchema, grantInput, () =>
          invalidArgument("Invalid refresh token grant input"),
        );

        const entries: Array<readonly [string, string]> = [];

        for (const [key, item] of Object.entries(value.parameters ?? {})) {
          entries.push([key, item]);
        }
        for (const resource of value.resources ?? []) {
          entries.push(["resource", resource]);
        }
        entries.push(["grant_type", "refresh_token"]);
        entries.push(["refresh_token", yield* reveal(value.refreshToken)]);
        if (value.scopes !== undefined && value.scopes.length > 0) {
          entries.push(["scope", value.scopes.join(scopeSeparator)]);
        }

        return yield* dispatch(entries);
      }),
    );

  return { codeGrant, refreshGrant };
});
