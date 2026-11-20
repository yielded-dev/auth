import * as Effect from "effect/Effect";
import * as Base64 from "effect/encoding/Base64";
import type * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import * as Ownership from "./internal/ownership.ts";
import * as Transport from "./internal/transport.ts";
import * as V from "./internal/validation.ts";
import * as OAuthError from "./OAuthError.ts";

export const JsonObject = V.JsonObject;
export type JsonObject = typeof JsonObject.Type;

/** HTTP loopback endpoints require an HTTP loopback issuer. Remote issuers
 * cannot downgrade endpoints to HTTP, including through discovery. */
export const Metadata = Schema.Struct({
  issuer: V.Issuer,
  authorization_endpoint: V.ProtocolEndpoint,
  token_endpoint: V.ProtocolEndpoint,
  jwks_uri: Schema.optionalKey(V.Endpoint),
  userinfo_endpoint: Schema.optionalKey(V.Endpoint),
  revocation_endpoint: Schema.optionalKey(V.ProtocolEndpoint),
  code_challenge_methods_supported: Schema.optionalKey(
    Schema.Array(V.text(64)).check(Schema.isMaxLength(64)),
  ),
  response_types_supported: Schema.optionalKey(
    Schema.Array(V.text(64)).check(Schema.isMaxLength(64)),
  ),
  grant_types_supported: Schema.optionalKey(
    Schema.Array(V.text(128)).check(Schema.isMaxLength(64)),
  ),
  id_token_signing_alg_values_supported: Schema.optionalKey(
    Schema.Array(V.text(64)).check(Schema.isMaxLength(64)),
  ),
  token_endpoint_auth_methods_supported: Schema.optionalKey(
    Schema.Array(V.text(64)).check(Schema.isMaxLength(64)),
  ),
  revocation_endpoint_auth_methods_supported: Schema.optionalKey(
    Schema.Array(V.text(64)).check(Schema.isMaxLength(64)),
  ),
  authorization_response_iss_parameter_supported: Schema.optionalKey(Schema.Boolean),
}).check(
  Schema.makeFilter((metadata) =>
    [
      metadata.authorization_endpoint,
      metadata.token_endpoint,
      metadata.jwks_uri,
      metadata.userinfo_endpoint,
      metadata.revocation_endpoint,
    ].every(
      (endpoint) => endpoint === undefined || V.endpointMatchesIssuer(metadata.issuer, endpoint),
    ),
  ),
);

export type Metadata = typeof Metadata.Type;

export const Authentication = Schema.Union([
  Schema.Struct({ method: Schema.Literal("client_secret_basic"), secret: V.secret(4096) }),
  Schema.Struct({
    method: Schema.Literal("client_secret_post"),
    /** Omit when each token request supplies clientSecret. */
    secret: Schema.optionalKey(V.secret(4096)),
  }),
  Schema.Struct({ method: Schema.Literal("none"), publicClient: Schema.Literal(true) }),
]);

export type Authentication = typeof Authentication.Type;

/** Uninterpreted private receipt. Inspect provider extensions before calling tokens. */
export const TokenReceipt = Schema.Struct({
  status: V.integer(100, 599),
  contentType: Schema.NullOr(Schema.String.check(Schema.isMaxLength(512))),
  body: Schema.Redacted(JsonObject, { disallowJsonEncode: true }),
});

export type TokenReceipt = typeof TokenReceipt.Type;

export const TokenSet = Schema.Struct({
  tokenType: Schema.Literal("bearer"),
  accessToken: V.secret(16384),
  refreshToken: Schema.optionalKey(V.secret(16384)),
  idToken: Schema.optionalKey(V.secret(65536)),
  expiresIn: Schema.optionalKey(Schema.Finite.check(Schema.isGreaterThanOrEqualTo(0))),
  scope: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16447))),
});

export type TokenSet = typeof TokenSet.Type;

export interface RequestOptions {
  readonly timeoutMs: number;
  readonly maxResponseBytes?: number;
}

export interface ClientOptions extends RequestOptions {
  readonly metadata: Metadata;
  readonly clientId: string;
  readonly authentication: Authentication;
  readonly profile?: {
    readonly url: string;
    readonly method?: "GET" | "POST";
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: string;
  };
  /** Defaults to form. Notion's token endpoint requires JSON. Repeated names,
   * including more than one `resource`, fail before the request. */
  readonly tokenBodyFormat?: "form" | "json";
  /** Defaults to a space. Linear's authorize URL requires commas. */
  readonly scopeSeparator?: " " | ",";
  readonly revocationAuthentication?: Authentication;
}

export interface Parameters {
  readonly parameters?: Readonly<Record<string, string>>;
  readonly resources?: ReadonlyArray<string>;
}

export interface AuthorizationInput extends Parameters {
  readonly redirectUri: string;
  readonly scopes: ReadonlyArray<string>;
  readonly state: Redacted.Redacted<string>;
  readonly codeChallenge?: string;
  readonly nonce?: Redacted.Redacted<string>;
  readonly maxAgeSeconds?: number;
  readonly prompt?: "none" | "login" | "consent" | "select_account";
  readonly loginHint?: string;
  /** Defaults to query. form_post is required by some issuers when name or
   * email scopes are requested. */
  readonly responseMode?: "query" | "form_post";
}

export interface CodeGrantInput extends Parameters {
  readonly code: Redacted.Redacted<string>;
  readonly redirectUri: string;
  readonly pkceVerifier?: Redacted.Redacted<string>;
  /** Used when client_secret_post has no stored secret. */
  readonly clientSecret?: Redacted.Redacted<string>;
}

export interface RefreshGrantInput extends Parameters {
  readonly refreshToken: Redacted.Redacted<string>;
  readonly scopes?: ReadonlyArray<string>;
  /** Used when client_secret_post has no stored secret. */
  readonly clientSecret?: Redacted.Redacted<string>;
}

export interface RevocationInput {
  readonly token: Redacted.Redacted<string>;
  readonly tokenTypeHint: "access_token" | "refresh_token";
  /** Used when client_secret_post has no stored secret. */
  readonly clientSecret?: Redacted.Redacted<string>;
}

export interface Client {
  readonly metadata: Metadata;
  readonly authorizationUrl: (
    input: AuthorizationInput,
  ) => Effect.Effect<Redacted.Redacted<string>, OAuthError.OAuthError>;
  readonly codeGrant: (input: CodeGrantInput) => Effect.Effect<TokenReceipt, OAuthError.OAuthError>;
  readonly refreshGrant: (
    input: RefreshGrantInput,
  ) => Effect.Effect<TokenReceipt, OAuthError.OAuthError>;
  readonly fetchProfile: (
    accessToken: Redacted.Redacted<string>,
  ) => Effect.Effect<JsonObject, OAuthError.OAuthError>;
  readonly revoke: (input: RevocationInput) => Effect.Effect<void, OAuthError.OAuthError>;
}

const ClientOptionsSchema = Schema.Struct({
  metadata: Metadata,
  clientId: V.text(1024),
  authentication: Authentication,
  ...V.RequestOptions.fields,
  profile: Schema.optionalKey(
    Schema.Struct({
      url: V.Endpoint,
      method: Schema.optionalKey(Schema.Literals(["GET", "POST"])),
      headers: Schema.optionalKey(V.Headers),
      body: Schema.optionalKey(V.text(4096)),
    }),
  ),
  tokenBodyFormat: Schema.optionalKey(Schema.Literals(["form", "json"])),
  scopeSeparator: Schema.optionalKey(Schema.Literals([" ", ","])),
  revocationAuthentication: Schema.optionalKey(Authentication),
}).check(
  Schema.makeFilter(
    (options) =>
      options.profile === undefined ||
      V.endpointMatchesIssuer(options.metadata.issuer, options.profile.url),
  ),
);

const additional = {
  parameters: Schema.optionalKey(V.Parameters),
  resources: Schema.optionalKey(V.Resources),
};

const Authorization = Schema.Struct({
  ...additional,
  redirectUri: V.Callback,
  scopes: V.Scopes,
  state: V.secret(256),
  codeChallenge: Schema.optionalKey(V.Challenge),
  nonce: Schema.optionalKey(V.secret(256)),
  maxAgeSeconds: Schema.optionalKey(V.integer(0, 86400)),
  prompt: Schema.optionalKey(Schema.Literals(["none", "login", "consent", "select_account"])),
  loginHint: Schema.optionalKey(V.text(1024)),
  responseMode: Schema.optionalKey(Schema.Literals(["query", "form_post"])),
});

const requestSecret = Schema.optionalKey(V.secret(8192));

const CodeGrant = Schema.Struct({
  ...additional,
  code: V.secret(16384),
  redirectUri: V.Callback,
  pkceVerifier: Schema.optionalKey(V.Verifier),
  clientSecret: requestSecret,
});

const RefreshGrant = Schema.Struct({
  ...additional,
  refreshToken: V.secret(16384),
  scopes: Schema.optionalKey(V.Scopes),
  clientSecret: requestSecret,
});

const Revocation = Schema.Struct({
  token: V.secret(16384),
  tokenTypeHint: Schema.Literals(["access_token", "refresh_token"]),
  clientSecret: requestSecret,
});

const ExpiresIn = Schema.Union([
  Schema.Finite,
  Schema.String.check(Schema.isPattern(/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u)).pipe(
    Schema.decodeTo(Schema.FiniteFromString),
  ),
]).check(Schema.isGreaterThanOrEqualTo(0));

const RawToken = Schema.Struct({
  access_token: V.text(16384),
  token_type: Schema.String.check(Schema.isPattern(/^[Bb][Ee][Aa][Rr][Ee][Rr]$/)),
  refresh_token: Schema.optionalKey(Schema.NullOr(V.text(16384))),
  id_token: Schema.optionalKey(V.text(65536)),
  expires_in: Schema.optionalKey(ExpiresIn),
  scope: Schema.optionalKey(
    Schema.Union([
      Schema.String.check(Schema.isMaxLength(16447)),
      Schema.Array(Schema.String.check(Schema.isMaxLength(1024))).check(Schema.isMaxLength(128)),
    ]),
  ),
});

const Terminal = Schema.Struct({
  error: V.text(128),
  error_description: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(4096))),
  error_uri: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(2048))),
});

const successFields = [
  "access_token",
  "refresh_token",
  "id_token",
  "token_type",
  "scope",
  "expires_in",
  "refresh_expires_in",
  "refresh_token_expires_in",
];

const invalidResponse = (
  endpoint: OAuthError.InvalidResponse["endpoint"],
  status: number,
  description: string,
): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.InvalidResponse({ endpoint, status, description }),
  });

const clientAuthFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.ClientAuthFailed({ description, cause }),
  });

/** Parse once provider-specific receipt checks have succeeded. expires_in accepts
 * finite nonnegative numbers and whole decimal strings (for example "60.5").
 * Whitespace, exponent/prefix syntax and nonfinite values are rejected. Raw
 * receipt extensions stay untouched. A null refresh token is omitted, and an
 * array scope is joined with spaces. No request, retry or claim verification. */
export const tokens = Effect.fnUntraced(function* (
  input: TokenReceipt,
): Effect.fn.Return<TokenSet, OAuthError.OAuthError> {
  const receipt = yield* V.decode(TokenReceipt, input, () =>
    V.invalidArgument("Invalid OAuth token receipt"),
  );

  if (!Transport.isJson(receipt.contentType))
    return yield* invalidResponse(
      "token",
      receipt.status,
      "Expected application/json token receipt",
    );

  const raw = yield* V.reveal(receipt.body, () =>
    V.invalidArgument("Token receipt body is unavailable"),
  );

  if (Object.hasOwn(raw, "error")) {
    if (successFields.some((key) => Object.hasOwn(raw, key)))
      return yield* invalidResponse(
        "token",
        receipt.status,
        "Token error response must not include token fields",
      );

    const terminal = yield* V.decode(Terminal, raw, () =>
      invalidResponse("token", receipt.status, "Invalid OAuth token error payload"),
    );

    if (receipt.status >= 400 && receipt.status < 500) {
      return yield* new OAuthError.OAuthError({
        reason: new OAuthError.EndpointError({
          endpoint: "token",
          status: receipt.status,
          ...V.normalizeOAuthErrorCode(terminal.error),
        }),
      });
    }

    return yield* invalidResponse(
      "token",
      receipt.status,
      "Token error payload returned with non-4xx HTTP status",
    );
  }
  if (
    receipt.status !== 200 ||
    Object.hasOwn(raw, "error_description") ||
    Object.hasOwn(raw, "error_uri")
  )
    return yield* invalidResponse("token", receipt.status, "Unexpected OAuth token response");

  const value = yield* V.decode(RawToken, raw, () =>
    invalidResponse("token", receipt.status, "Invalid OAuth token response payload"),
  );

  const scope: string | undefined =
    typeof value.scope === "string"
      ? value.scope
      : value.scope === undefined
        ? undefined
        : value.scope.join(" ");

  if (scope !== undefined && scope.length > 16447)
    return yield* invalidResponse("token", receipt.status, "Token scope exceeds maximum length");

  return {
    tokenType: "bearer",
    accessToken: Redacted.make(value.access_token),
    ...(value.refresh_token === undefined || value.refresh_token === null
      ? {}
      : { refreshToken: Redacted.make(value.refresh_token) }),
    ...(value.id_token === undefined ? {} : { idToken: Redacted.make(value.id_token) }),
    ...(value.expires_in === undefined ? {} : { expiresIn: value.expires_in }),
    ...(scope === undefined ? {} : { scope }),
  };
});

const parameters = (input: Parameters) => {
  const values = new URLSearchParams(input.parameters);

  for (const resource of input.resources ?? []) values.append("resource", resource);

  return values;
};

// RFC6749 Appendix B: encode client credentials before joining with the colon.
// Adapted from oauth4webapi 3.8.8 src/index.ts::formUrlEncode (MIT, Filip Skokan).
// Exact source commit and license: ../THIRD_PARTY_NOTICES.md.
const basicComponent = (value: string) =>
  encodeURIComponent(value).replace(/[-_.!~*'()]|%20/gu, (part) =>
    part === "%20" ? "+" : `%${part.charCodeAt(0).toString(16).toUpperCase()}`,
  );

const authenticated = Effect.fnUntraced(function* (
  url: string,
  clientId: string,
  authentication: Authentication,
  body: URLSearchParams,
  format: "form" | "json" = "form",
  clientSecret?: Redacted.Redacted<string>,
) {
  let request = HttpClientRequest.post(url).pipe(HttpClientRequest.acceptJson);

  if (authentication.method === "client_secret_basic") {
    const secret = yield* V.reveal(authentication.secret, () =>
      clientAuthFailed("Client secret is unavailable"),
    );

    const credential = yield* Effect.try({
      try: () => Base64.encode(`${basicComponent(clientId)}:${basicComponent(secret)}`),
      catch: (cause) => clientAuthFailed("Could not encode HTTP Basic client credentials", cause),
    });

    request = HttpClientRequest.setHeader(request, "authorization", `Basic ${credential}`);
  } else {
    body.set("client_id", clientId);
    if (authentication.method === "client_secret_post") {
      const secret = authentication.secret ?? clientSecret;

      if (secret === undefined)
        return yield* clientAuthFailed("Missing client secret for client_secret_post");
      body.set(
        "client_secret",
        yield* V.reveal(secret, () => clientAuthFailed("Client secret is unavailable")),
      );
      if (authentication.secret === undefined) Redacted.wipeUnsafe(secret);
    }
  }

  if (format === "json") {
    const seen = new Set<string>();

    for (const key of body.keys()) {
      if (seen.has(key))
        return yield* V.invalidArgument("JSON token request cannot contain repeated parameters");
      seen.add(key);
    }
  }

  const encoded =
    format === "json" ? JSON.stringify(Object.fromEntries(body.entries())) : body.toString();

  if (new TextEncoder().encode(encoded).length > 131072)
    return yield* V.invalidArgument("Encoded token request body exceeds maximum size");

  return HttpClientRequest.bodyText(
    request,
    encoded,
    format === "json" ? "application/json" : "application/x-www-form-urlencoded;charset=UTF-8",
  );
});

/** One installed client, exact endpoints, private credentials and owning Scope.
 * Supply an HttpClient without retry/redirect/cookie middleware. Fetch injection
 * active at construction is captured. Owner closure cancels and joins active
 * operations, then rejects their results as unavailable; caller interruption
 * cancels and joins its operation without closing the client. Unexpected
 * cleanup failures remain observable in the operation's Cause. */
export const make = Effect.fnUntraced(function* (
  input: ClientOptions,
): Effect.fn.Return<Client, OAuthError.OAuthError, HttpClient.HttpClient | Scope.Scope> {
  const options = yield* V.configuration(
    ClientOptionsSchema,
    input,
    "Invalid OAuth client options",
  );

  const authentication = yield* detachAuthentication(options.authentication);

  const revocationAuthentication =
    options.revocationAuthentication === undefined
      ? authentication
      : yield* detachAuthentication(options.revocationAuthentication);

  const metadata = V.freeze(options.metadata);

  const supported =
    metadata.token_endpoint_auth_methods_supported ??
    (metadata.jwks_uri === undefined ? undefined : ["client_secret_basic"]);

  const revokeSupported =
    metadata.revocation_endpoint_auth_methods_supported ??
    (metadata.jwks_uri === undefined ? undefined : ["client_secret_basic"]);

  if (
    (supported !== undefined && !supported.includes(authentication.method)) ||
    (options.revocationAuthentication !== undefined &&
      metadata.revocation_endpoint !== undefined &&
      revokeSupported !== undefined &&
      !revokeSupported.includes(revocationAuthentication.method))
  )
    return yield* V.invalidArgument("Client authentication method is not supported by metadata");
  const { available, use } = yield* Ownership.make("token");
  const http = yield* Transport.capture;
  const profile = options.profile === undefined ? undefined : V.freeze(options.profile);

  const tokenBodyFormat =
    options.tokenBodyFormat === "json" ? ("json" as const) : ("form" as const);

  const scopeSeparator = options.scopeSeparator === "," ? "," : " ";

  if (
    profile !== undefined &&
    (profile.method === undefined || profile.method === "GET") &&
    profile.body !== undefined
  )
    return yield* V.invalidArgument("GET profile requests cannot include a body");

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      if (authentication.method !== "none" && authentication.secret !== undefined)
        Redacted.wipeUnsafe(authentication.secret);
      if (
        revocationAuthentication.method !== "none" &&
        revocationAuthentication.secret !== undefined
      )
        Redacted.wipeUnsafe(revocationAuthentication.secret);
    }),
  );

  const send = Effect.fnUntraced(function* (
    body: URLSearchParams,
    clientSecret?: Redacted.Redacted<string>,
  ) {
    yield* available;

    const request = yield* authenticated(
      new URL(metadata.token_endpoint).href,
      options.clientId,
      authentication,
      body,
      tokenBodyFormat,
      clientSecret,
    );

    return yield* Transport.json(
      yield* Transport.request(http, request, options, "token"),
      "token",
    );
  });

  const authorizationUrl = Effect.fnUntraced(function* (input: AuthorizationInput) {
    yield* available;
    const value = yield* V.configuration(Authorization, input, "Invalid authorization parameters");
    const url = new URL(metadata.authorization_endpoint);
    const body = parameters(value);

    body.set("client_id", options.clientId);
    body.set("redirect_uri", value.redirectUri);
    body.set("response_type", "code");
    body.set("response_mode", value.responseMode === "form_post" ? "form_post" : "query");
    if (value.scopes.length > 0) body.set("scope", value.scopes.join(scopeSeparator));
    body.set("state", yield* V.reveal(value.state));
    if (value.codeChallenge !== undefined) {
      body.set("code_challenge", value.codeChallenge);
      body.set("code_challenge_method", "S256");
    }
    if (value.nonce !== undefined) body.set("nonce", yield* V.reveal(value.nonce));
    if (value.maxAgeSeconds !== undefined) body.set("max_age", String(value.maxAgeSeconds));
    if (value.prompt !== undefined) body.set("prompt", value.prompt);
    if (value.loginHint !== undefined) body.set("login_hint", value.loginHint);
    for (const [key, item] of body) url.searchParams.append(key, item);
    if (url.href.length > 16384)
      return yield* V.invalidArgument("Authorization URL exceeds maximum length");

    return Redacted.make(url.href);
  }, use);

  const codeGrant = Effect.fnUntraced(function* (input: CodeGrantInput) {
    yield* available;

    const value = yield* V.configuration(
      CodeGrant,
      input,
      "Invalid authorization code grant input",
    );

    const body = parameters(value);

    body.set("grant_type", "authorization_code");
    body.set("code", yield* V.reveal(value.code));
    if (value.pkceVerifier !== undefined)
      body.set("code_verifier", yield* V.reveal(value.pkceVerifier));
    body.set("redirect_uri", value.redirectUri);

    return yield* send(body, value.clientSecret);
  }, use);

  const refreshGrant = Effect.fnUntraced(function* (input: RefreshGrantInput) {
    yield* available;
    const value = yield* V.configuration(RefreshGrant, input, "Invalid refresh token grant input");
    const body = parameters(value);

    body.set("grant_type", "refresh_token");
    body.set("refresh_token", yield* V.reveal(value.refreshToken));
    if (value.scopes !== undefined && value.scopes.length > 0)
      body.set("scope", value.scopes.join(scopeSeparator));

    return yield* send(body, value.clientSecret);
  }, use);

  const fetchProfile = Effect.fnUntraced(function* (input: Redacted.Redacted<string>) {
    yield* available;
    if (profile === undefined) return yield* V.invalidArgument("No profile endpoint is configured");

    const token = yield* V.reveal(
      yield* V.decode(Bearer, input, () => V.invalidArgument("Invalid bearer access token")),
    );

    const url = new URL(profile.url).href;

    let request = (
      profile.method === "POST" ? HttpClientRequest.post(url) : HttpClientRequest.get(url)
    ).pipe(
      HttpClientRequest.acceptJson,
      HttpClientRequest.setHeaders(profile.headers ?? {}),
      HttpClientRequest.setHeader("authorization", `Bearer ${token}`),
    );

    if (profile.method === "POST" && profile.body !== undefined)
      request = HttpClientRequest.bodyText(request, profile.body, "application/json");

    const response = yield* Transport.request(http, request, options, "userinfo");

    if (response.status !== 200)
      return yield* invalidResponse(
        "userinfo",
        response.status,
        "Unexpected profile response status",
      );

    return yield* V.reveal((yield* Transport.json(response, "userinfo")).body);
  }, use);

  const revoke = Effect.fnUntraced(function* (input: RevocationInput) {
    yield* available;
    if (metadata.revocation_endpoint === undefined)
      return yield* V.invalidArgument("No revocation endpoint is configured");
    if (revokeSupported !== undefined && !revokeSupported.includes(revocationAuthentication.method))
      return yield* V.invalidArgument(
        "Revocation authentication method is not supported by metadata",
      );
    const value = yield* V.configuration(Revocation, input, "Invalid revocation input");

    const request = yield* authenticated(
      new URL(metadata.revocation_endpoint).href,
      options.clientId,
      revocationAuthentication,
      new URLSearchParams({
        token: yield* V.reveal(value.token),
        token_type_hint: value.tokenTypeHint,
      }),
      "form",
      value.clientSecret,
    );

    const response = yield* Transport.request(http, request, options, "revocation");

    if (response.status === 200) return;

    if (response.status >= 400 && response.status < 500 && Transport.isJson(response.contentType)) {
      const parsed = yield* Transport.json(response, "revocation").pipe(
        Effect.flatMap((document) => V.reveal(document.body)),
        Effect.flatMap((raw) => V.decode(Terminal, raw)),
        Effect.option,
      );

      if (parsed._tag === "Some") {
        return yield* new OAuthError.OAuthError({
          reason: new OAuthError.EndpointError({
            endpoint: "revocation",
            status: response.status,
            ...V.normalizeOAuthErrorCode(parsed.value.error),
          }),
        });
      }
    }

    return yield* invalidResponse(
      "revocation",
      response.status,
      "Unexpected revocation response status",
    );
  }, use);

  return { metadata, authorizationUrl, codeGrant, refreshGrant, fetchProfile, revoke };
});

const Bearer = Schema.Redacted(V.text(16384).check(Schema.isPattern(/^[A-Za-z0-9._~+/-]+=*$/u)), {
  disallowJsonEncode: true,
});

const detachAuthentication = Effect.fnUntraced(function* (
  authentication: Authentication,
): Effect.fn.Return<Authentication, OAuthError.OAuthError> {
  if (authentication.method === "none") return { ...authentication };
  if (authentication.method === "client_secret_post" && authentication.secret === undefined)
    return { method: "client_secret_post" };
  if (authentication.secret === undefined)
    return yield* clientAuthFailed("Missing client secret for configured authentication method");

  return {
    ...authentication,
    secret: Redacted.make(
      yield* V.reveal(authentication.secret, () =>
        clientAuthFailed("Client secret is unavailable"),
      ),
    ),
  };
});
