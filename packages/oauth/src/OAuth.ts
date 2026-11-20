/**
 * OAuth 2.1 relying-party client service, authorization transactions, and
 * single-attempt token exchange and revocation.
 *
 * {@link make} and {@link layer} bind a client ID, {@link ClientAuth.Method},
 * optional separate `revocationAuth`, {@link Discovery.Discovery}, and
 * `HttpClient` within an owning `Scope`. {@link authorize} generates fresh
 * `state` and optional PKCE `S256` entropy and delegates to
 * `client.prepareAuthorization` so the authorization URL and
 * {@link Transaction} are built from one metadata snapshot.
 *
 * **Gotchas**
 *
 * `exchange` and `exchangeRaw` are interruptible, single-attempt, and scoped
 * through the bounded response read. Never automatically retry an ambiguous
 * token exchange or revocation. `response_mode` is omitted on authorization
 * URLs for `"query"` (the default for `response_type=code`) and emitted only
 * for `"form_post"`.
 *
 * @stability unstable
 * @since 4.1.4
 */
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import type * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import type * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as Layer from "effect/Layer";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import * as ClientAuth from "./ClientAuth.ts";
import * as Discovery from "./Discovery.ts";
import * as Grant from "./Grant.ts";
import * as Ownership from "./internal/ownership.ts";
import * as Transport from "./internal/transport.ts";
import * as V from "./internal/validation.ts";
import * as OAuthError from "./OAuthError.ts";
import * as Pkce from "./Pkce.ts";

/**
 * Authorization callback delivery mode.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type ResponseMode = "query" | "form_post";

/**
 * RFC 9207 authorization-response `iss` parameter policy.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type IssuerIdentificationMode = "required" | "optional" | "unsupported";

/**
 * Schema for a serializable authorization ceremony transaction.
 *
 * Uses `Schema.RedactedFromValue`, `DateTimeUtcFromMillis`, and
 * `DurationFromMillis` so transactions can be sealed directly with `Jwt.encrypt`.
 *
 * @stability unstable
 * @category schemas
 * @since 4.1.4
 */
export const Transaction: Schema.Struct<{
  readonly issuer: Schema.String;
  readonly clientId: Schema.String;
  readonly state: Schema.RedactedFromValue<Schema.String>;
  readonly redirectUri: Schema.String;
  readonly responseMode: Schema.Literals<readonly ["query", "form_post"]>;
  readonly issuerIdentification: Schema.Literals<readonly ["required", "optional", "unsupported"]>;
  readonly scopes: Schema.$Array<Schema.String>;
  readonly requestedAt: Schema.DateTimeUtcFromMillis;
  readonly expiresAt: Schema.DateTimeUtcFromMillis;
  readonly pkceVerifier: Schema.optionalKey<Schema.RedactedFromValue<Schema.String>>;
  readonly nonce: Schema.optionalKey<Schema.RedactedFromValue<Schema.String>>;
  readonly maxAge: Schema.optionalKey<Schema.DurationFromMillis>;
  readonly resources: Schema.optionalKey<Schema.$Array<Schema.String>>;
}> = Schema.Struct({
  issuer: V.Issuer,
  clientId: V.text(1024),
  state: Schema.RedactedFromValue(V.text(256)),
  redirectUri: V.Callback,
  responseMode: Schema.Literals(["query", "form_post"]),
  issuerIdentification: Schema.Literals(["required", "optional", "unsupported"]),
  scopes: V.Scopes,
  requestedAt: Schema.DateTimeUtcFromMillis,
  expiresAt: Schema.DateTimeUtcFromMillis,
  pkceVerifier: Schema.optionalKey(Pkce.Verifier),
  nonce: Schema.optionalKey(Schema.RedactedFromValue(V.text(256))),
  maxAge: Schema.optionalKey(Schema.DurationFromMillis),
  resources: Schema.optionalKey(V.Resources),
});

/**
 * A prepared OAuth 2.1 authorization transaction bound to an issuer and client.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type Transaction = typeof Transaction.Type;

/**
 * Output of {@link Client} `prepareAuthorization`, {@link authorize}, and
 * `Oidc.authorize`: a redacted authorization URL and its matching
 * {@link Transaction}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface Authorization {
  readonly url: Redacted.Redacted<string>;
  readonly transaction: Transaction;
}

/**
 * Options for building a low-level authorization URL via
 * `client.authorizationUrl`.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface AuthorizationUrlOptions {
  readonly redirectUri: string;
  readonly scopes: ReadonlyArray<string>;
  readonly state: string | Redacted.Redacted<string>;
  readonly codeChallenge?: string | undefined;
  readonly nonce?: string | Redacted.Redacted<string> | undefined;
  readonly maxAge?: Duration.Input | undefined;
  readonly prompt?: "none" | "login" | "consent" | "select_account" | undefined;
  readonly loginHint?: string | undefined;
  readonly responseMode?: ResponseMode | undefined;
  readonly resources?: ReadonlyArray<string> | undefined;
  readonly parameters?: Readonly<Record<string, string>> | undefined;
}

/**
 * Options for `client.prepareAuthorization`, accepting caller-supplied `state`,
 * optional PKCE pair, and optional `nonce`.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface PrepareAuthorizationOptions {
  readonly redirectUri: string;
  readonly scopes: ReadonlyArray<string>;
  readonly state: string | Redacted.Redacted<string>;
  readonly pkce?:
    | {
        readonly verifier: string | Redacted.Redacted<string>;
        readonly challenge: string;
      }
    | undefined;
  readonly nonce?: string | Redacted.Redacted<string> | undefined;
  readonly requireAdvertisedPkce?: boolean | undefined;
  readonly maxAge?: Duration.Input | undefined;
  readonly lifetime?: Duration.Input | undefined;
  readonly issuerIdentification?: IssuerIdentificationMode | undefined;
  readonly prompt?: "none" | "login" | "consent" | "select_account" | undefined;
  readonly loginHint?: string | undefined;
  readonly responseMode?: ResponseMode | undefined;
  readonly resources?: ReadonlyArray<string> | undefined;
  readonly parameters?: Readonly<Record<string, string>> | undefined;
}

/**
 * Options for {@link authorize}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface AuthorizeOptions {
  readonly redirectUri: string;
  readonly scopes: ReadonlyArray<string>;
  readonly pkce?: boolean | undefined;
  readonly requireAdvertisedPkce?: boolean | undefined;
  readonly maxAge?: Duration.Input | undefined;
  readonly lifetime?: Duration.Input | undefined;
  readonly issuerIdentification?: IssuerIdentificationMode | undefined;
  readonly prompt?: "none" | "login" | "consent" | "select_account" | undefined;
  readonly loginHint?: string | undefined;
  readonly responseMode?: ResponseMode | undefined;
  readonly resources?: ReadonlyArray<string> | undefined;
  readonly parameters?: Readonly<Record<string, string>> | undefined;
}

/**
 * Configuration for {@link make} and {@link layer}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface ClientOptions<out R = never, out RR = never> {
  readonly clientId: string;
  readonly clientAuth: ClientAuth.Method<R>;
  readonly revocationAuth?: ClientAuth.Method<RR> | undefined;
  readonly allowUnauthenticatedClientCredentials?: boolean | undefined;
  readonly timeout?: Duration.Input | undefined;
  readonly maxResponseBytes?: number | undefined;
}

/**
 * Scoped OAuth 2.1 client service bound to `Discovery`, `HttpClient`, and
 * client authentication methods captured at construction.
 *
 * @stability unstable
 * @category services
 * @since 4.1.4
 */
export class Client extends Context.Service<
  Client,
  {
    readonly clientId: string;
    readonly clientAuthName: string;
    readonly authorizationUrl: (
      options: AuthorizationUrlOptions,
    ) => Effect.Effect<Redacted.Redacted<string>, OAuthError.OAuthError>;
    readonly prepareAuthorization: (
      options: PrepareAuthorizationOptions,
    ) => Effect.Effect<Authorization, OAuthError.OAuthError>;
    readonly exchangeRaw: (
      grant: Grant.Grant,
    ) => Effect.Effect<Grant.TokenReceipt, OAuthError.OAuthError>;
    readonly exchange: (grant: Grant.Grant) => Effect.Effect<Grant.TokenSet, OAuthError.OAuthError>;
    readonly revoke: (options: {
      readonly token: string | Redacted.Redacted<string>;
      readonly tokenTypeHint?: "access_token" | "refresh_token" | undefined;
    }) => Effect.Effect<void, OAuthError.OAuthError>;
  }
>()("effect/oauth/OAuth/Client") {}

const utf8Encoder = new TextEncoder();
const maxTokenRequestBytes = 131072;
const maxAuthorizationUrlLength = 16384;
const defaultMaxResponseBytes = 1048576;

const forbiddenAuthHeaders: ReadonlySet<string> = new Set([
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

const PromptSchema = Schema.Literals(["none", "login", "consent", "select_account"]);
const ResponseModeSchema = Schema.Literals(["query", "form_post"]);
const IssuerIdentificationSchema = Schema.Literals(["required", "optional", "unsupported"]);
const TokenTypeHintSchema = Schema.Literals(["access_token", "refresh_token"]);

const Terminal = Schema.Struct({
  error: V.text(128),
  error_description: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(4096))),
  error_uri: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(2048))),
});

const clientAuthFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.ClientAuthFailed({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const invalidResponse = (
  endpoint: OAuthError.InvalidResponse["endpoint"],
  status: number,
  description: string,
): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.InvalidResponse({ endpoint, status, description }),
  });

const decodeNonEmptySecret = (
  value: string | Redacted.Redacted<string>,
  maxLength: number,
  name: string,
): Effect.Effect<string, OAuthError.OAuthError> =>
  V.revealString(
    value,
    () => V.invalidArgument(`${name} is unavailable`),
    () => V.invalidArgument(`Invalid ${name}`),
  ).pipe(
    Effect.filterOrFail(
      (item) => item.length > 0 && item.length <= maxLength,
      () => V.invalidArgument(`Invalid ${name}`),
    ),
  );

const buildAuthorizationUrl = Effect.fnUntraced(function* (
  authorizationEndpoint: string,
  clientId: string,
  input: {
    readonly redirectUri: string;
    readonly scopes: ReadonlyArray<string>;
    readonly state: string;
    readonly codeChallenge?: string | undefined;
    readonly nonce?: string | undefined;
    readonly maxAgeSeconds?: number | undefined;
    readonly prompt?: "none" | "login" | "consent" | "select_account" | undefined;
    readonly loginHint?: string | undefined;
    readonly responseMode?: ResponseMode | undefined;
    readonly resources?: ReadonlyArray<string> | undefined;
    readonly parameters?: Readonly<Record<string, string>> | undefined;
  },
): Effect.fn.Return<Redacted.Redacted<string>, OAuthError.OAuthError> {
  const url = new URL(authorizationEndpoint);
  const body = new URLSearchParams(input.parameters);

  for (const resource of input.resources ?? []) body.append("resource", resource);

  body.set("client_id", clientId);
  body.set("redirect_uri", input.redirectUri);
  body.set("response_type", "code");
  if (input.responseMode === "form_post") body.set("response_mode", "form_post");
  if (input.scopes.length > 0) body.set("scope", input.scopes.join(" "));
  body.set("state", input.state);
  if (input.codeChallenge !== undefined) {
    body.set("code_challenge", input.codeChallenge);
    body.set("code_challenge_method", "S256");
  }
  if (input.nonce !== undefined) body.set("nonce", input.nonce);
  if (input.maxAgeSeconds !== undefined) body.set("max_age", String(input.maxAgeSeconds));
  if (input.prompt !== undefined) body.set("prompt", input.prompt);
  if (input.loginHint !== undefined) body.set("login_hint", input.loginHint);

  for (const [key, item] of body) url.searchParams.append(key, item);
  if (url.href.length > maxAuthorizationUrlLength) {
    return yield* V.invalidArgument("Authorization URL exceeds maximum length");
  }

  return Redacted.make(url.href);
});

const parseSharedAuthOptions = Effect.fnUntraced(function* (
  options: AuthorizationUrlOptions | PrepareAuthorizationOptions,
) {
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid authorization parameters");
  }

  const redirectUri = yield* V.configuration(
    V.Callback,
    options.redirectUri,
    "Invalid redirectUri",
  );

  const scopes = yield* V.configuration(V.Scopes, options.scopes, "Invalid authorization scopes");
  const state = yield* decodeNonEmptySecret(options.state, 256, "state");

  const nonce =
    options.nonce === undefined
      ? undefined
      : yield* decodeNonEmptySecret(options.nonce, 256, "nonce");

  const maxAgeSeconds =
    options.maxAge === undefined ? undefined : yield* V.wholeSeconds("maxAge", options.maxAge);

  const prompt =
    options.prompt === undefined
      ? undefined
      : yield* V.configuration(PromptSchema, options.prompt, "Invalid prompt");

  const loginHint =
    options.loginHint === undefined
      ? undefined
      : yield* V.configuration(V.text(1024), options.loginHint, "Invalid loginHint");

  const responseMode =
    options.responseMode === undefined
      ? undefined
      : yield* V.configuration(ResponseModeSchema, options.responseMode, "Invalid responseMode");

  const resources =
    options.resources === undefined
      ? undefined
      : yield* V.configuration(V.Resources, options.resources, "Invalid authorization resources");

  const parameters =
    options.parameters === undefined
      ? undefined
      : yield* V.configuration(
          V.Parameters,
          options.parameters,
          "Invalid authorization parameters",
        );

  return {
    redirectUri,
    scopes,
    state,
    nonce,
    maxAgeSeconds,
    prompt,
    loginHint,
    responseMode,
    resources,
    parameters,
  };
});

const assembleAuthenticatedRequest = Effect.fnUntraced(function* (
  endpointUrl: string,
  clientId: string,
  applied: ClientAuth.Applied,
  baseParams: ReadonlyArray<readonly [string, string]>,
  forbidGrantTypeInAuth: boolean,
): Effect.fn.Return<HttpClientRequest.HttpClientRequest, OAuthError.OAuthError> {
  if (
    !Predicate.isObject(applied) ||
    !Predicate.isObject(applied.headers) ||
    !Array.isArray(applied.form)
  ) {
    return yield* clientAuthFailed("Client authentication method returned an invalid result");
  }

  const headers: Record<string, string> = {};
  const seenHeaders = new Set<string>();
  let hasBasicAuthorization = false;

  for (const name of Object.keys(applied.headers)) {
    const lower = name.toLowerCase();

    if (
      !headerNamePattern.test(name) ||
      forbiddenAuthHeaders.has(lower) ||
      seenHeaders.has(lower)
    ) {
      return yield* clientAuthFailed("Client authentication method emitted a disallowed header");
    }

    const descriptor = Object.getOwnPropertyDescriptor(applied.headers, name);

    if (descriptor === undefined || !("value" in descriptor)) {
      return yield* clientAuthFailed("Client authentication method header is unreadable");
    }

    const headerValue = yield* V.revealString(
      descriptor.value as string | Redacted.Redacted<string>,
      () => clientAuthFailed("Client authentication header credential is unavailable"),
      () => clientAuthFailed("Client authentication header value must be a string"),
    );

    if (/[\r\n]/u.test(headerValue)) {
      return yield* clientAuthFailed(
        "Client authentication header value contains control characters",
      );
    }

    seenHeaders.add(lower);
    if (lower === "authorization" && /^\s*Basic\s+/i.test(headerValue)) {
      hasBasicAuthorization = true;
    }

    Object.defineProperty(headers, name, {
      value: headerValue,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }

  const body = new URLSearchParams();
  const reservedBaseKeys = new Set<string>();

  for (const [key, value] of baseParams) {
    reservedBaseKeys.add(key.toLowerCase());
    body.append(key, value);
  }

  let hasClientIdInForm = false;

  for (const entry of applied.form) {
    if (!Array.isArray(entry) || entry.length !== 2) {
      return yield* clientAuthFailed("Client authentication method emitted an invalid form field");
    }

    const key: unknown = entry[0];
    const value: unknown = entry[1];

    if (
      typeof key !== "string" ||
      key.length === 0 ||
      key.length > 256 ||
      // oxlint-disable-next-line no-control-regex -- Reject control characters in auth form field names.
      /[\r\n\u0000-\u001f\u007f]/u.test(key)
    ) {
      return yield* clientAuthFailed("Client authentication method emitted an invalid form field");
    }

    const lower = key.toLowerCase();

    if ((forbidGrantTypeInAuth && lower === "grant_type") || reservedBaseKeys.has(lower)) {
      return yield* clientAuthFailed(
        forbidGrantTypeInAuth
          ? "Client authentication method cannot override grant parameters"
          : "Client authentication method cannot override revocation parameters",
      );
    }

    const revealed = yield* V.revealString(
      value as string | Redacted.Redacted<string>,
      () => clientAuthFailed("Client authentication form credential is unavailable"),
      () => clientAuthFailed("Client authentication form value must be a string"),
    );

    if (lower === "client_id") hasClientIdInForm = true;
    body.append(key, revealed);
  }

  if (!hasBasicAuthorization && !hasClientIdInForm) {
    body.append("client_id", clientId);
  }

  const encoded = body.toString();

  if (utf8Encoder.encode(encoded).length > maxTokenRequestBytes) {
    return yield* V.invalidArgument("Encoded token request body exceeds maximum size");
  }

  let request = HttpClientRequest.post(endpointUrl).pipe(HttpClientRequest.acceptJson);

  for (const [name, value] of Object.entries(headers)) {
    request = HttpClientRequest.setHeader(request, name, value);
  }

  return HttpClientRequest.bodyText(
    request,
    encoded,
    "application/x-www-form-urlencoded;charset=UTF-8",
  );
});

const validateMetadataEndpoints = Effect.fnUntraced(function* (
  metadata: Discovery.Metadata,
  requiredEndpoint: "authorization" | "token" | "revocation",
): Effect.fn.Return<{ readonly issuer: string; readonly endpoint: string }, OAuthError.OAuthError> {
  if (!Predicate.isObject(metadata)) {
    return yield* V.invalidArgument("Discovery metadata is invalid");
  }

  const issuer = yield* V.decode(V.Issuer, metadata.issuer, () =>
    V.invalidArgument("Discovery metadata issuer is invalid"),
  );

  const rawEndpoint =
    requiredEndpoint === "authorization"
      ? metadata.authorization_endpoint
      : requiredEndpoint === "token"
        ? metadata.token_endpoint
        : metadata.revocation_endpoint;

  if (rawEndpoint === undefined) {
    return yield* V.invalidArgument(
      `Discovery metadata does not include ${requiredEndpoint}_endpoint`,
    );
  }

  const endpoint = yield* V.decode(V.ProtocolEndpoint, rawEndpoint, () =>
    V.invalidArgument(`Discovery metadata ${requiredEndpoint}_endpoint is invalid`),
  );

  if (!V.endpointMatchesIssuer(issuer, endpoint)) {
    return yield* V.invalidArgument(
      `Discovery metadata ${requiredEndpoint}_endpoint scheme does not match issuer`,
    );
  }

  return { issuer, endpoint };
});

/**
 * Builds a scoped OAuth 2.1 {@link Client} service.
 *
 * Options are validated eagerly with zero network I/O during construction.
 * Supply an `HttpClient` without retry, redirect, or cookie middleware.
 * Closing the owning `Scope` cancels and joins active operations and rejects
 * later calls with `TransportFailed`.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const make: <R = never, RR = never>(
  options: ClientOptions<R, RR>,
) => Effect.Effect<
  Client["Service"],
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient | Scope.Scope | R | RR
> = Effect.fnUntraced(function* <R = never, RR = never>(
  options: ClientOptions<R, RR>,
): Effect.fn.Return<
  Client["Service"],
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient | Scope.Scope | R | RR
> {
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid OAuth client options");
  }

  const clientId = yield* V.configuration(V.text(1024), options.clientId, "Invalid OAuth clientId");

  if (!ClientAuth.isMethod(options.clientAuth)) {
    return yield* V.invalidArgument("Invalid clientAuth method");
  }

  const clientAuthName = yield* V.configuration(
    V.text(64),
    options.clientAuth.name,
    "Invalid clientAuth method name",
  );

  const clientAuth = options.clientAuth;

  let revocationAuth: ClientAuth.Method<R | RR> = clientAuth;

  if (options.revocationAuth !== undefined) {
    if (!ClientAuth.isMethod(options.revocationAuth)) {
      return yield* V.invalidArgument("Invalid revocationAuth method");
    }
    yield* V.configuration(
      V.text(64),
      options.revocationAuth.name,
      "Invalid revocationAuth method name",
    );
    revocationAuth = options.revocationAuth;
  }

  if (
    options.allowUnauthenticatedClientCredentials !== undefined &&
    typeof options.allowUnauthenticatedClientCredentials !== "boolean"
  ) {
    return yield* V.invalidArgument("allowUnauthenticatedClientCredentials must be a boolean");
  }

  const allowUnauthenticatedClientCredentials =
    options.allowUnauthenticatedClientCredentials ?? false;

  const timeoutMs = yield* V.positiveFiniteMillis("timeout", options.timeout ?? "10 seconds");

  const maxResponseBytes = yield* V.positiveInteger(
    "maxResponseBytes",
    options.maxResponseBytes ?? defaultMaxResponseBytes,
  );

  if (maxResponseBytes > defaultMaxResponseBytes) {
    return yield* V.invalidArgument(
      `maxResponseBytes must not exceed ${defaultMaxResponseBytes} bytes`,
    );
  }

  const requestLimits: Transport.Options = { timeoutMs, maxResponseBytes };
  const discovery = yield* Discovery.Discovery;
  const http = yield* Transport.capture;
  const authContext = yield* Effect.context<R | RR>();
  const tokenOwnership = yield* Ownership.make("token");
  const revocationOwnership = yield* Ownership.make("revocation");

  const authorizationUrl = Effect.fnUntraced(function* (
    input: AuthorizationUrlOptions,
  ): Effect.fn.Return<Redacted.Redacted<string>, OAuthError.OAuthError> {
    yield* tokenOwnership.available;

    const shared = yield* parseSharedAuthOptions(input);

    const codeChallenge =
      input.codeChallenge === undefined
        ? undefined
        : yield* V.configuration(V.Challenge, input.codeChallenge, "Invalid codeChallenge");

    const metadata = yield* discovery.resolve;
    const { endpoint } = yield* validateMetadataEndpoints(metadata, "authorization");

    return yield* buildAuthorizationUrl(endpoint, clientId, {
      ...shared,
      codeChallenge,
    });
  }, tokenOwnership.use);

  const prepareAuthorization = Effect.fnUntraced(function* (
    input: PrepareAuthorizationOptions,
  ): Effect.fn.Return<Authorization, OAuthError.OAuthError> {
    yield* tokenOwnership.available;

    const shared = yield* parseSharedAuthOptions(input);

    if (
      input.requireAdvertisedPkce !== undefined &&
      typeof input.requireAdvertisedPkce !== "boolean"
    ) {
      return yield* V.invalidArgument("requireAdvertisedPkce must be a boolean");
    }

    const requireAdvertisedPkce = input.requireAdvertisedPkce ?? false;

    const requestedIssuerIdentification =
      input.issuerIdentification === undefined
        ? undefined
        : yield* V.configuration(
            IssuerIdentificationSchema,
            input.issuerIdentification,
            "Invalid issuerIdentification",
          );

    const lifetimeMs = yield* V.positiveFiniteMillis("lifetime", input.lifetime ?? "10 minutes");

    let pkceVerifier: string | undefined;
    let codeChallenge: string | undefined;

    if (input.pkce === undefined) {
      if (clientAuthName === "none") {
        return yield* V.invalidArgument("Public clients require PKCE");
      }
    } else {
      if (!Predicate.isObject(input.pkce)) {
        return yield* V.invalidArgument("Invalid PKCE pair");
      }

      const rawVerifier = yield* V.revealString(
        input.pkce.verifier,
        () => V.invalidArgument("PKCE verifier is unavailable"),
        () => V.invalidArgument("Invalid PKCE verifier"),
      );

      yield* V.configuration(V.Verifier, Redacted.make(rawVerifier), "Invalid PKCE verifier");
      codeChallenge = yield* V.configuration(
        V.Challenge,
        input.pkce.challenge,
        "Invalid PKCE challenge",
      );
      pkceVerifier = rawVerifier;
    }

    // Resolve discovery metadata once so URL and Transaction derive from the
    // exact same snapshot.
    const metadata = yield* discovery.resolve;
    const { issuer, endpoint } = yield* validateMetadataEndpoints(metadata, "authorization");

    if (pkceVerifier !== undefined) {
      const supportedPkce = metadata.code_challenge_methods_supported;

      if (supportedPkce !== undefined) {
        if (!Array.isArray(supportedPkce) || !supportedPkce.includes("S256")) {
          return yield* V.invalidArgument("Authorization server does not support S256 PKCE");
        }
      } else if (requireAdvertisedPkce) {
        return yield* V.invalidArgument(
          "Authorization server does not advertise S256 PKCE support",
        );
      }
    }

    let issuerIdentification: IssuerIdentificationMode;

    if (metadata.authorization_response_iss_parameter_supported === true) {
      if (
        requestedIssuerIdentification !== undefined &&
        requestedIssuerIdentification !== "required"
      ) {
        return yield* V.invalidArgument(
          "Cannot downgrade issuerIdentification when server advertises iss support",
        );
      }
      issuerIdentification = "required";
    } else {
      issuerIdentification = requestedIssuerIdentification ?? "unsupported";
    }

    const responseMode: ResponseMode = shared.responseMode ?? "query";

    const url = yield* buildAuthorizationUrl(endpoint, clientId, {
      ...shared,
      responseMode,
      codeChallenge,
    });

    const nowMillis = yield* Clock.currentTimeMillis;

    const transaction: Transaction = {
      issuer,
      clientId,
      state: Redacted.make(shared.state),
      redirectUri: shared.redirectUri,
      responseMode,
      issuerIdentification,
      scopes: [...shared.scopes],
      requestedAt: DateTime.makeUnsafe(nowMillis),
      expiresAt: DateTime.makeUnsafe(nowMillis + lifetimeMs),
      ...(pkceVerifier === undefined ? {} : { pkceVerifier: Redacted.make(pkceVerifier) }),
      ...(shared.nonce === undefined ? {} : { nonce: Redacted.make(shared.nonce) }),
      ...(shared.maxAgeSeconds === undefined
        ? {}
        : { maxAge: Duration.seconds(shared.maxAgeSeconds) }),
      ...(shared.resources === undefined ? {} : { resources: [...shared.resources] }),
    };

    return { url, transaction };
  }, tokenOwnership.use);

  const exchangeRaw = Effect.fnUntraced(function* (
    grant: Grant.Grant,
  ): Effect.fn.Return<Grant.TokenReceipt, OAuthError.OAuthError> {
    yield* tokenOwnership.available;

    const resolved = yield* Grant.resolveGrant(grant);

    if (
      resolved.grantType.trim() === "client_credentials" &&
      clientAuthName === "none" &&
      !allowUnauthenticatedClientCredentials
    ) {
      return yield* V.invalidArgument("client_credentials grant requires client authentication");
    }

    if (resolved.clientId !== undefined && resolved.clientId !== clientId) {
      return yield* V.invalidArgument("Grant clientId does not match OAuth client");
    }

    const metadata = yield* discovery.resolve;
    const { issuer, endpoint } = yield* validateMetadataEndpoints(metadata, "token");

    if (resolved.issuer !== undefined && resolved.issuer !== issuer) {
      return yield* V.invalidArgument("Grant issuer does not match authorization server");
    }

    const supported =
      metadata.token_endpoint_auth_methods_supported ??
      (metadata.jwks_uri === undefined ? undefined : ["client_secret_basic"]);

    if (supported !== undefined && !supported.includes(clientAuthName)) {
      return yield* V.invalidArgument("Client authentication method is not supported by metadata");
    }

    const endpointUrl = new URL(endpoint).href;

    const applied = yield* clientAuth
      .apply({ clientId, endpoint: endpointUrl, issuer })
      .pipe(Effect.provideContext(authContext));

    const request = yield* assembleAuthenticatedRequest(
      endpointUrl,
      clientId,
      applied,
      [["grant_type", resolved.grantType], ...resolved.parameters],
      true,
    ).pipe(Effect.ensuring(Effect.sync(() => ClientAuth.wipeApplied(applied))));

    const response = yield* Transport.request(http, request, requestLimits, "token");

    return yield* Transport.json(response, "token");
  }, tokenOwnership.use);

  const exchange = (grant: Grant.Grant): Effect.Effect<Grant.TokenSet, OAuthError.OAuthError> =>
    Effect.flatMap(exchangeRaw(grant), Grant.parseTokens);

  const revoke = Effect.fnUntraced(function* (input: {
    readonly token: string | Redacted.Redacted<string>;
    readonly tokenTypeHint?: "access_token" | "refresh_token" | undefined;
  }): Effect.fn.Return<void, OAuthError.OAuthError> {
    yield* revocationOwnership.available;

    if (!Predicate.isObject(input)) {
      return yield* V.invalidArgument("Invalid revocation input");
    }

    const token = yield* decodeNonEmptySecret(input.token, 16384, "token");

    const tokenTypeHint =
      input.tokenTypeHint === undefined
        ? undefined
        : yield* V.configuration(TokenTypeHintSchema, input.tokenTypeHint, "Invalid tokenTypeHint");

    const metadata = yield* discovery.resolve;
    const { issuer, endpoint } = yield* validateMetadataEndpoints(metadata, "revocation");

    const revokeSupported =
      metadata.revocation_endpoint_auth_methods_supported ??
      (metadata.jwks_uri === undefined ? undefined : ["client_secret_basic"]);

    if (revokeSupported !== undefined && !revokeSupported.includes(revocationAuth.name)) {
      return yield* V.invalidArgument(
        "Revocation authentication method is not supported by metadata",
      );
    }

    const endpointUrl = new URL(endpoint).href;

    const applied = yield* revocationAuth
      .apply({ clientId, endpoint: endpointUrl, issuer })
      .pipe(Effect.provideContext(authContext));

    const baseParams: Array<readonly [string, string]> = [["token", token]];

    if (tokenTypeHint !== undefined) {
      baseParams.push(["token_type_hint", tokenTypeHint]);
    }

    const request = yield* assembleAuthenticatedRequest(
      endpointUrl,
      clientId,
      applied,
      baseParams,
      false,
    ).pipe(Effect.ensuring(Effect.sync(() => ClientAuth.wipeApplied(applied))));

    const response = yield* Transport.request(http, request, requestLimits, "revocation");

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
  }, revocationOwnership.use);

  return Client.of({
    clientId,
    clientAuthName,
    authorizationUrl,
    prepareAuthorization,
    exchangeRaw,
    exchange,
    revoke,
  });
});

/**
 * Layer that provides {@link Client} built by {@link make}. Closing the layer
 * cancels and joins any in-flight token or revocation requests.
 *
 * @stability unstable
 * @category layers
 * @since 4.1.4
 */
export const layer: <R = never, RR = never>(
  options: ClientOptions<R, RR>,
) => Layer.Layer<
  Client,
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient | R | RR
> = (options) => Layer.effect(Client, make(options));

/**
 * Generates fresh `state` and optional PKCE `S256` entropy (`pkce` defaults to
 * `true`) and prepares an {@link Authorization} through the registered
 * {@link Client} service.
 *
 * @stability unstable
 * @category authorization
 * @since 4.1.4
 */
export const authorize: (
  options: AuthorizeOptions,
) => Effect.Effect<
  Authorization,
  OAuthError.OAuthError,
  Client | Digest.Digest | SecureRandom.SecureRandom
> = Effect.fnUntraced(function* (
  options: AuthorizeOptions,
): Effect.fn.Return<
  Authorization,
  OAuthError.OAuthError,
  Client | Digest.Digest | SecureRandom.SecureRandom
> {
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid authorization options");
  }
  if (options.pkce !== undefined && typeof options.pkce !== "boolean") {
    return yield* V.invalidArgument("pkce must be a boolean");
  }

  const client = yield* Client;
  const usePkce = options.pkce ?? true;

  if (!usePkce && client.clientAuthName === "none") {
    return yield* V.invalidArgument("Public clients require PKCE");
  }

  const random = yield* SecureRandom.SecureRandom;
  const stateBytes = yield* random.randomBytes(32);

  if (stateBytes.length !== 32) {
    return yield* Effect.die(
      new RangeError("SecureRandom.randomBytes(32) returned an unexpected byte length"),
    );
  }

  const state = Redacted.make(Base64Url.encode(stateBytes));
  const pkce = usePkce ? yield* Pkce.generate : undefined;
  const { pkce: _pkce, ...rest } = options;

  return yield* client.prepareAuthorization({
    ...rest,
    state,
    ...(pkce === undefined ? {} : { pkce }),
  });
});
