import * as OAuth from "@yielded/oauth/OAuth";
import * as OAuthError from "@yielded/oauth/OAuthError";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Base64 from "effect/encoding/Base64";
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

export const defaultMaxResponseBytes = 1_048_576;
export const maxTokenRequestBytes = 131_072;
export const maxAuthorizationUrlLength = 16_384;

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

const clientAuthFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.ClientAuthFailed({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

// Mirror of `@yielded/oauth` `internal/validation.ts`; keep in sync until M4b.
export const text = (maximum: number) => Schema.NonEmptyString.check(Schema.isMaxLength(maximum));

const integer = (minimum: number, maximum: number) =>
  Schema.Int.check(Schema.isBetween({ minimum, maximum }));

export const secret = (maximum: number) =>
  Schema.Redacted(text(maximum), { disallowJsonEncode: true });

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
export const ScopeName = Schema.String.check(Schema.isPattern(/^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/));

export const Scopes = Schema.Array(ScopeName).check(
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

const reservedParameters: ReadonlySet<string> = new Set([
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

const Parameters = Schema.Record(
  Schema.String.check(Schema.isPattern(/^[A-Za-z][A-Za-z0-9._~-]{0,63}$/)),
  Schema.String.check(Schema.isMaxLength(2048)),
).check(
  Schema.makeFilter(
    (value) =>
      Object.keys(value).length <= 16 &&
      Object.keys(value).every((key) => !reservedParameters.has(key.toLowerCase())),
  ),
);

const ProtocolEndpoint = Endpoint.check(
  Schema.makeFilter((value) =>
    Array.from(new URL(value).searchParams.keys()).every(
      (key) => !reservedParameters.has(key.toLowerCase()),
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

export const Headers = Schema.Record(
  Schema.String.check(Schema.isPattern(/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/)),
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

export const isJsonContentType = (contentType: string | null): boolean =>
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

// Mirror of `@yielded/oauth` `internal/transport.ts`; keep in sync until M4b.
/** Single-attempt bounded HTTP request with manual redirect rejection,
 * `response.url` verification, `Scope`-owned byte folding, and cause-preserving timeout. */
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
              : transportFailed(endpoint, "HTTP transport request failed", { cause: error }),
          ),
        ),
      ),
      timeoutOrElseWithCause({
        duration: options.timeoutMs,
        orElse: () => Effect.fail(transportFailed(endpoint, "HTTP request timed out")),
      }),
    ),
);

const JsonObjectFromString = Schema.fromJsonString(OAuth.JsonObject);

/** Parse a bounded `application/json` object response reusing `@yielded/oauth`'s
 * plain-JSON schema validation. */
export const parseJsonResponse = Effect.fnUntraced(function* (
  response: HttpResponse,
  endpoint: OAuthError.InvalidResponse["endpoint"],
): Effect.fn.Return<OAuth.TokenReceipt, OAuthError.OAuthError> {
  if (!isJsonContentType(response.contentType)) {
    return yield* invalidResponse(endpoint, response.status, "Expected application/json response");
  }

  const bytes = yield* reveal(response.bytes, () =>
    invalidResponse(endpoint, response.status, "Response body is unavailable"),
  );

  const decoded = yield* Effect.try({
    try: () => new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    catch: () => invalidResponse(endpoint, response.status, "Response body is not valid UTF-8"),
  });

  const body = yield* decode(JsonObjectFromString, decoded, () =>
    invalidResponse(endpoint, response.status, "Response body is not a bounded JSON object"),
  );

  return {
    status: response.status,
    contentType: response.contentType,
    body: Redacted.make(freezePlainJson(body)),
  };
});

/** Build an authorization URL whose `scope` query parameter is comma-delimited.
 * Validates individual `ScopeName` entries first so multi-scope lists whose
 * joined wire string exceeds 256 characters still succeed under the 16,384-char
 * final URL cap. */
export const authorizationUrlWithCommaScopes = Effect.fnUntraced(function* (
  client: OAuth.Client,
  input: OAuth.AuthorizationInput,
): Effect.fn.Return<Redacted.Redacted<string>, OAuthError.OAuthError> {
  const scopes = yield* decode(Scopes, input.scopes, () =>
    invalidArgument("Invalid authorization scopes"),
  );

  const first = scopes[0];

  if (first === undefined) return yield* client.authorizationUrl({ ...input, scopes: [] });

  // Reserve `scope`'s exact query-parameter slot before rewriting its value in place.
  const base = yield* client.authorizationUrl({ ...input, scopes: [first] });

  const url = new URL(
    yield* reveal(base, () => invalidArgument("Authorization URL is unavailable")),
  );

  url.searchParams.set("scope", scopes.join(","));

  if (url.href.length > maxAuthorizationUrlLength) {
    return yield* invalidArgument("Authorization URL exceeds maximum length");
  }

  return Redacted.make(url.href);
});

// Mirror of `@yielded/oauth` `OAuth.ts` auth and grant assembly; keep in sync until M4b.
const TokenSenderOptionsSchema = Schema.Struct({
  issuer: Issuer,
  tokenEndpoint: ProtocolEndpoint,
  clientId: text(1024),
  authentication: OAuth.Authentication,
  ...RequestOptions.fields,
  tokenBodyFormat: Schema.optionalKey(Schema.Literals(["form", "json"])),
  scopeSeparator: Schema.optionalKey(Schema.Literals([" ", ","])),
}).check(
  Schema.makeFilter((options) => endpointMatchesIssuer(options.issuer, options.tokenEndpoint)),
);

const requestSecret = Schema.optionalKey(secret(8192));

const CodeGrantSchema = Schema.Struct({
  parameters: Schema.optionalKey(Parameters),
  resources: Schema.optionalKey(Resources),
  code: secret(16384),
  redirectUri: Callback,
  pkceVerifier: Schema.optionalKey(Verifier),
  clientSecret: requestSecret,
});

const RefreshGrantSchema = Schema.Struct({
  parameters: Schema.optionalKey(Parameters),
  resources: Schema.optionalKey(Resources),
  refreshToken: secret(16384),
  scopes: Schema.optionalKey(Scopes),
  clientSecret: requestSecret,
});

// RFC6749 Appendix B: encode client credentials before joining with the colon.
// Adapted from oauth4webapi 3.8.8 src/index.ts::formUrlEncode (MIT, Filip Skokan).
// Exact source commit and license: ../../../../THIRD_PARTY_NOTICES.md.
const basicComponent = (value: string): string =>
  encodeURIComponent(value).replace(/[-_.!~*'()]|%20/gu, (part) =>
    part === "%20" ? "+" : `%${part.charCodeAt(0).toString(16).toUpperCase()}`,
  );

const detachAuthentication = Effect.fnUntraced(function* (
  authentication: OAuth.Authentication,
): Effect.fn.Return<OAuth.Authentication, OAuthError.OAuthError> {
  if (authentication.method === "none") return { ...authentication };
  if (authentication.method === "client_secret_post" && authentication.secret === undefined) {
    return { method: "client_secret_post" };
  }
  if (authentication.secret === undefined) {
    return yield* clientAuthFailed("Missing client secret for configured authentication method");
  }

  return {
    ...authentication,
    secret: Redacted.make(
      yield* reveal(authentication.secret, () => clientAuthFailed("Client secret is unavailable")),
    ),
  };
});

const assembleParameters = (input: OAuth.Parameters): URLSearchParams => {
  const values = new URLSearchParams(input.parameters);

  for (const resource of input.resources ?? []) values.append("resource", resource);

  return values;
};

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

const buildAuthenticatedTokenRequest = Effect.fnUntraced(function* (
  url: string,
  clientId: string,
  authentication: OAuth.Authentication,
  body: URLSearchParams,
  format: "form" | "json",
  clientSecret?: Redacted.Redacted<string>,
): Effect.fn.Return<HttpClientRequest.HttpClientRequest, OAuthError.OAuthError> {
  let request = HttpClientRequest.post(url).pipe(HttpClientRequest.acceptJson);

  if (authentication.method === "client_secret_basic") {
    const revealed = yield* reveal(authentication.secret, () =>
      clientAuthFailed("Client secret is unavailable"),
    );

    const credential = yield* Effect.try({
      try: () => Base64.encode(`${basicComponent(clientId)}:${basicComponent(revealed)}`),
      catch: (cause) => clientAuthFailed("Could not encode HTTP Basic client credentials", cause),
    });

    request = HttpClientRequest.setHeader(request, "authorization", `Basic ${credential}`);
  } else {
    body.set("client_id", clientId);
    if (authentication.method === "client_secret_post") {
      const resolvedSecret = authentication.secret ?? clientSecret;

      if (resolvedSecret === undefined) {
        return yield* clientAuthFailed("Missing client secret for client_secret_post");
      }

      body.set(
        "client_secret",
        yield* reveal(resolvedSecret, () => clientAuthFailed("Client secret is unavailable")),
      );
      if (authentication.secret === undefined) Redacted.wipeUnsafe(resolvedSecret);
    }
  }

  const encoded = format === "json" ? yield* encodeJsonObject(body.entries()) : body.toString();

  if (utf8Encoder.encode(encoded).length > maxTokenRequestBytes) {
    return yield* invalidArgument("Encoded token request body exceeds maximum size");
  }

  return HttpClientRequest.bodyText(
    request,
    encoded,
    format === "json" ? "application/json" : "application/x-www-form-urlencoded;charset=UTF-8",
  );
});

export interface AuthenticatedTokenSenderOptions {
  readonly issuer: string;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly authentication: OAuth.Authentication;
  readonly timeoutMs: number;
  readonly maxResponseBytes?: number;
  readonly tokenBodyFormat?: "form" | "json";
  readonly scopeSeparator?: " " | ",";
}

export interface AuthenticatedTokenSender {
  readonly codeGrant: (
    input: OAuth.CodeGrantInput,
  ) => Effect.Effect<OAuth.TokenReceipt, OAuthError.OAuthError>;
  readonly refreshGrant: (
    input: OAuth.RefreshGrantInput,
  ) => Effect.Effect<OAuth.TokenReceipt, OAuthError.OAuthError>;
}

/** Scoped, single-attempt token endpoint sender supporting vendor wire formats
 * (JSON token bodies and comma-delimited refresh scopes) across all client
 * authentication methods (`client_secret_basic`, `client_secret_post`, `none`). */
export const makeAuthenticatedTokenSender = Effect.fnUntraced(function* (
  input: AuthenticatedTokenSenderOptions,
): Effect.fn.Return<
  AuthenticatedTokenSender,
  OAuthError.OAuthError,
  HttpClient.HttpClient | Scope.Scope
> {
  const options = yield* decode(TokenSenderOptionsSchema, input, () =>
    invalidArgument("Invalid OAuth token sender options"),
  );

  const authentication = yield* detachAuthentication(options.authentication);
  const tokenUrl = new URL(options.tokenEndpoint).href;
  const format = options.tokenBodyFormat === "json" ? ("json" as const) : ("form" as const);
  const scopeSeparator = options.scopeSeparator === "," ? "," : " ";
  const http = yield* captureHardenedHttp;

  const run = yield* makeScopedOperation(() =>
    transportFailed("token", "The owning scope is closed"),
  );

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      if (authentication.method !== "none" && authentication.secret !== undefined) {
        Redacted.wipeUnsafe(authentication.secret);
      }
    }),
  );

  const dispatch = Effect.fnUntraced(function* (
    body: URLSearchParams,
    clientSecret?: Redacted.Redacted<string>,
  ) {
    const request = yield* buildAuthenticatedTokenRequest(
      tokenUrl,
      options.clientId,
      authentication,
      body,
      format,
      clientSecret,
    );

    const response = yield* sendRequest(http, request, options, "token");

    return yield* parseJsonResponse(response, "token");
  });

  const codeGrant = (grantInput: OAuth.CodeGrantInput) =>
    run(
      Effect.gen(function* () {
        const value = yield* decode(CodeGrantSchema, grantInput, () =>
          invalidArgument("Invalid authorization code grant input"),
        );

        const body = assembleParameters(value);

        body.set("grant_type", "authorization_code");
        body.set("code", yield* reveal(value.code));
        if (value.pkceVerifier !== undefined) {
          body.set("code_verifier", yield* reveal(value.pkceVerifier));
        }
        body.set("redirect_uri", value.redirectUri);

        return yield* dispatch(body, value.clientSecret);
      }),
    );

  const refreshGrant = (grantInput: OAuth.RefreshGrantInput) =>
    run(
      Effect.gen(function* () {
        const value = yield* decode(RefreshGrantSchema, grantInput, () =>
          invalidArgument("Invalid refresh token grant input"),
        );

        const body = assembleParameters(value);

        body.set("grant_type", "refresh_token");
        body.set("refresh_token", yield* reveal(value.refreshToken));
        if (value.scopes !== undefined && value.scopes.length > 0) {
          body.set("scope", value.scopes.join(scopeSeparator));
        }

        return yield* dispatch(body, value.clientSecret);
      }),
    );

  return { codeGrant, refreshGrant };
});
