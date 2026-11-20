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
import * as Mac from "effect/crypto/Mac";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import type * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import * as ClientAuth from "./ClientAuth.ts";
import * as Discovery from "./Discovery.ts";
import * as Grant from "./Grant.ts";
import * as InternalClientAuth from "./internal/clientAuth.ts";
import * as InternalGrant from "./internal/grant.ts";
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
 * Decoded authorization callback outcome: either a redacted authorization
 * `Code` with optional `scope` and allowlisted `extra` parameters, or a
 * normalized `Error` carrying a closed {@link OAuthError.OAuthErrorCode}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type CallbackOutcome =
  | {
      readonly _tag: "Code";
      readonly code: Redacted.Redacted<string>;
      readonly scope?: string | undefined;
      readonly extra: Readonly<Record<string, string>>;
    }
  | {
      readonly _tag: "Error";
      readonly code: OAuthError.OAuthErrorCode;
      readonly rawCode?: string | undefined;
    };

/**
 * Decoded authorization callback parameters preserving delivery transport
 * `mode`, redacted `state`, optional RFC 9207 `issuer`, and {@link CallbackOutcome}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface CallbackParams {
  readonly mode: ResponseMode;
  readonly state: Redacted.Redacted<string>;
  readonly issuer?: string | undefined;
  readonly outcome: CallbackOutcome;
}

/**
 * Options for {@link callbackParamsFromQuery} and {@link callbackParamsFromFormPost}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface CallbackDecodeOptions {
  /**
   * Additional non-standard parameter names retained in `outcome.extra` (and
   * permitted when `unknownParameters` is `"reject"`). Standard OAuth callback
   * parameters are handled directly and never copied into `extra`.
   */
  readonly allowedParameters?: ReadonlyArray<string> | undefined;
  /**
   * Policy for unrecognized parameters outside the standard set and
   * `allowedParameters`. Defaults to `"ignore"` (RFC 6749 §4.1.2).
   */
  readonly unknownParameters?: "ignore" | "reject" | undefined;
}

/**
 * Validated authorization callback code result returned by {@link validateCallback}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface CallbackResult {
  readonly code: Redacted.Redacted<string>;
  readonly issuer?: string | undefined;
  readonly scope?: string | undefined;
  readonly extra: Readonly<Record<string, string>>;
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

const PromptSchema = Schema.Literals(["none", "login", "consent", "select_account"]);
const ResponseModeSchema = Schema.Literals(["query", "form_post"]);
const IssuerIdentificationSchema = Schema.Literals(["required", "optional", "unsupported"]);
const TokenTypeHintSchema = Schema.Literals(["access_token", "refresh_token"]);

const Terminal = Schema.Struct({
  error: V.text(128),
  error_description: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(4096))),
  error_uri: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(2048))),
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
  requireWellFormedUnicode = false,
): Effect.Effect<string, OAuthError.OAuthError> =>
  V.revealString(
    value,
    () => V.invalidArgument(`${name} is unavailable`),
    () => V.invalidArgument(`Invalid ${name}`),
  ).pipe(
    Effect.filterOrFail(
      (item) =>
        item.length > 0 &&
        item.length <= maxLength &&
        (!requireWellFormedUnicode || V.isWellFormedUnicode(item)),
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
  const state = yield* decodeNonEmptySecret(options.state, 256, "state", true);

  const nonce =
    options.nonce === undefined
      ? undefined
      : yield* decodeNonEmptySecret(options.nonce, 256, "nonce", true);

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

const encodeFormRequest = Effect.fnUntraced(function* (
  endpointUrl: string,
  prepared: ClientAuth.PreparedRequest,
): Effect.fn.Return<HttpClientRequest.HttpClientRequest, OAuthError.OAuthError> {
  const body = new URLSearchParams();

  for (const [key, value] of prepared.parameters) {
    body.append(key, value);
  }

  const encoded = body.toString();

  if (utf8Encoder.encode(encoded).length > maxTokenRequestBytes) {
    return yield* V.invalidArgument("Encoded token request body exceeds maximum size");
  }

  let request = HttpClientRequest.post(endpointUrl).pipe(HttpClientRequest.acceptJson);

  for (const [name, value] of Object.entries(prepared.headers)) {
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

  if (!InternalClientAuth.isMethod(options.clientAuth)) {
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
    if (!InternalClientAuth.isMethod(options.revocationAuth)) {
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

    // Bind the complete effective ordered resource list (endpoint query
    // `resource`s, `parameters.resource`, and `options.resources`) so URL and
    // Transaction cannot disagree.
    const endpointResources = new URL(endpoint).searchParams.getAll("resource");
    let parameterResource: string | undefined;

    if (shared.parameters !== undefined) {
      for (const [key, value] of Object.entries(shared.parameters)) {
        if (key === "resource") {
          parameterResource = value;
        } else if (key.toLowerCase() === "resource") {
          return yield* V.invalidArgument("Invalid authorization resource parameter");
        }
      }
    }

    const combinedResources = [
      ...endpointResources,
      ...(parameterResource === undefined ? [] : [parameterResource]),
      ...(shared.resources ?? []),
    ];

    const effectiveResources =
      combinedResources.length === 0
        ? undefined
        : yield* V.configuration(V.Resources, combinedResources, "Invalid authorization resources");

    const responseMode: ResponseMode = shared.responseMode ?? "query";

    const nowMillis = yield* Clock.currentTimeMillis;
    const requestedAt = DateTime.make(nowMillis);
    const expiresAt = DateTime.make(nowMillis + lifetimeMs);

    if (Option.isNone(requestedAt) || Option.isNone(expiresAt)) {
      return yield* V.invalidArgument(
        "Authorization transaction lifetime produces an invalid expiration",
      );
    }

    const url = yield* buildAuthorizationUrl(endpoint, clientId, {
      ...shared,
      responseMode,
      codeChallenge,
    });

    const transaction: Transaction = {
      issuer,
      clientId,
      state: Redacted.make(shared.state),
      redirectUri: shared.redirectUri,
      responseMode,
      issuerIdentification,
      scopes: [...shared.scopes],
      requestedAt: requestedAt.value,
      expiresAt: expiresAt.value,
      ...(pkceVerifier === undefined ? {} : { pkceVerifier: Redacted.make(pkceVerifier) }),
      ...(shared.nonce === undefined ? {} : { nonce: Redacted.make(shared.nonce) }),
      ...(shared.maxAgeSeconds === undefined
        ? {}
        : { maxAge: Duration.seconds(shared.maxAgeSeconds) }),
      ...(effectiveResources === undefined ? {} : { resources: [...effectiveResources] }),
    };

    return { url, transaction };
  }, tokenOwnership.use);

  const exchangeRaw = Effect.fnUntraced(function* (
    grant: Grant.Grant,
  ): Effect.fn.Return<Grant.TokenReceipt, OAuthError.OAuthError> {
    yield* tokenOwnership.available;

    const resolved = yield* InternalGrant.resolveGrant(grant);

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

    const request = yield* ClientAuth.withPreparedRequest(
      clientAuth,
      { clientId, endpoint: endpointUrl, issuer },
      [
        ...resolved.leadingParameters,
        ["grant_type", resolved.grantType],
        ...resolved.trailingParameters,
      ],
      (prepared) => encodeFormRequest(endpointUrl, prepared),
      { forbidGrantType: true },
    ).pipe(Effect.provideContext(authContext));

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
    const baseParams: Array<readonly [string, string]> = [["token", token]];

    if (tokenTypeHint !== undefined) {
      baseParams.push(["token_type_hint", tokenTypeHint]);
    }

    const request = yield* ClientAuth.withPreparedRequest(
      revocationAuth,
      { clientId, endpoint: endpointUrl, issuer },
      baseParams,
      (prepared) => encodeFormRequest(endpointUrl, prepared),
      { forbidGrantType: false },
    ).pipe(Effect.provideContext(authContext));

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

  stateBytes.fill(0);

  const pkce = usePkce ? yield* Pkce.generate : undefined;
  const { pkce: _pkce, ...rest } = options;

  return yield* client.prepareAuthorization({
    ...rest,
    state,
    ...(pkce === undefined ? {} : { pkce }),
  });
});

const maxCallbackParams = 32;
const maxAllowedCallbackParameters = 256;
const maxCallbackValueLength = 4096;
const maxCallbackScopeLength = 16384;
const maxCallbackQueryLength = 262144;
const defaultMaxFormPostBytes = 16384;
const maxCallbackClockToleranceMillis = 300_000;

// RFC 6749 Appendix A.11: code = 1*VSCHAR (%x20-7E).
const authorizationCodePattern = /^[\x20-\x7e]+$/;

// RFC 6749 §4.1.2.1: error values MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E.
const authorizationErrorPattern = /^[\x20\x21\x23-\x5b\x5d-\x7e]+$/;

// Callback issuer equality matches the issuance issuer contract without
// imposing Discovery's URL/no-query/no-well-known restrictions.
const CallbackIssuer = V.text(2048).check(
  // oxlint-disable-next-line no-control-regex -- Reject whitespace, backslash, and ASCII controls.
  Schema.isPattern(/^[^\s\\\u0000-\u001f\u007f]+$/),
  Schema.makeFilter((value) => V.isWellFormedUnicode(value)),
);

const standardCallbackParameters: ReadonlySet<string> = new Set([
  "state",
  "code",
  "error",
  "error_description",
  "error_uri",
  "iss",
  "scope",
]);

const forbiddenCallbackParameters: ReadonlySet<string> = new Set([
  "access_token",
  "id_token",
  "token",
  "token_type",
  "expires_in",
  "response",
]);

const forbiddenCallbackKeys: ReadonlySet<string> = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

const knownCallbackErrorCodes: ReadonlySet<string> = new Set<OAuthError.OAuthErrorCode>([
  "invalid_request",
  "invalid_client",
  "invalid_grant",
  "unauthorized_client",
  "unsupported_grant_type",
  "unsupported_response_type",
  "unsupported_token_type",
  "invalid_scope",
  "invalid_target",
  "invalid_token",
  "insufficient_scope",
  "access_denied",
  "interaction_required",
  "login_required",
  "account_selection_required",
  "consent_required",
  "temporarily_unavailable",
  "server_error",
  "other",
]);

const callbackRejected = (reason: OAuthError.CallbackRejected["reason"]): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.CallbackRejected({ reason }),
  });

const defineExtraProperty = (target: Record<string, string>, key: string, value: string): void => {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
};

const parseCallbackDecodeOptions = Effect.fnUntraced(function* (
  options: CallbackDecodeOptions | undefined,
): Effect.fn.Return<
  {
    readonly allowed: ReadonlySet<string>;
    readonly unknownParameters: "ignore" | "reject";
  },
  OAuthError.OAuthError
> {
  if (options === undefined) {
    return { allowed: new Set<string>(), unknownParameters: "ignore" };
  }
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid callback decode options");
  }

  const unknownParameters = options.unknownParameters ?? "ignore";

  if (unknownParameters !== "ignore" && unknownParameters !== "reject") {
    return yield* V.invalidArgument('unknownParameters must be "ignore" or "reject"');
  }

  const allowed = new Set<string>();

  if (options.allowedParameters !== undefined) {
    if (
      !Array.isArray(options.allowedParameters) ||
      options.allowedParameters.length > maxAllowedCallbackParameters
    ) {
      return yield* V.invalidArgument("Invalid allowedParameters");
    }

    for (const key of options.allowedParameters) {
      if (
        typeof key !== "string" ||
        key.length === 0 ||
        key.length > 256 ||
        !V.isWellFormedUnicode(key) ||
        // oxlint-disable-next-line no-control-regex -- Reject control characters in allowed parameter names.
        /[\u0000-\u001f\u007f]/u.test(key) ||
        forbiddenCallbackKeys.has(key) ||
        forbiddenCallbackParameters.has(key.toLowerCase())
      ) {
        return yield* V.invalidArgument("Invalid entry in allowedParameters");
      }
      allowed.add(key);
    }
  }

  return { allowed, unknownParameters };
});

const checkUrlEncodedBounds = Effect.fnUntraced(function* (
  raw: string,
): Effect.fn.Return<void, OAuthError.OAuthError> {
  if (raw.length > maxCallbackQueryLength) {
    return yield* callbackRejected("invalidParameters");
  }

  let segments = 0;
  let start = 0;

  for (let index = 0; index <= raw.length; index++) {
    if (index === raw.length || raw.charCodeAt(index) === 38) {
      if (index > start) {
        segments += 1;
        if (segments > maxCallbackParams) {
          return yield* callbackRejected("invalidParameters");
        }
      }
      start = index + 1;
    }
  }
});

const parseUrlEncodedString = Effect.fnUntraced(function* (
  raw: string,
): Effect.fn.Return<ReadonlyArray<readonly [string, string]>, OAuthError.OAuthError> {
  yield* checkUrlEncodedBounds(raw);

  // Prefix `&` when `raw` starts with `?` so URLSearchParams does not strip a
  // literal leading `?` belonging to the first parameter name.
  const params = new URLSearchParams(raw.startsWith("?") ? `&${raw}` : raw);
  const entries: Array<readonly [string, string]> = [];

  for (const [key, value] of params) {
    entries.push([key, value]);
  }

  return entries;
});

const extractCallbackUrl = (
  input: string | { readonly href: string },
): Effect.Effect<readonly [string, URL], OAuthError.OAuthError> =>
  Effect.gen(function* () {
    let rawUrl: string;

    if (typeof input === "string") {
      rawUrl = input;
    } else if (Predicate.isObject(input) && "href" in input) {
      const href = yield* Effect.try({
        try: () => (input as { readonly href: unknown }).href,
        catch: () => callbackRejected("invalidTransport"),
      });

      if (typeof href !== "string") {
        return yield* V.invalidArgument("Callback URL href must be a string");
      }
      rawUrl = href;
    } else {
      return yield* V.invalidArgument("Invalid callback URL");
    }

    if (rawUrl.includes("#")) {
      return yield* callbackRejected("invalidTransport");
    }

    const parsed = yield* Effect.try({
      try: () => new URL(rawUrl),
      catch: () => callbackRejected("invalidTransport"),
    });

    return [rawUrl, parsed] as const;
  });

const isFormUrlEncodedContentType = (contentType: string | undefined): boolean => {
  if (typeof contentType !== "string") return false;
  const parts = contentType.split(";");

  if (parts[0]?.trim().toLowerCase() !== "application/x-www-form-urlencoded") {
    return false;
  }

  for (const rawParam of parts.slice(1)) {
    const param = rawParam.trim();

    if (param.length === 0) continue;
    const eq = param.indexOf("=");

    if (eq <= 0) return false;
    const name = param.slice(0, eq).trim().toLowerCase();
    let value = param.slice(eq + 1).trim();

    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    if (name === "charset" && value.toLowerCase() !== "utf-8") {
      return false;
    }
  }

  return true;
};

const decodeCallbackEntries = Effect.fnUntraced(function* (
  mode: ResponseMode,
  entries: ReadonlyArray<readonly [string, string]>,
  options: {
    readonly allowed: ReadonlySet<string>;
    readonly unknownParameters: "ignore" | "reject";
  },
): Effect.fn.Return<CallbackParams, OAuthError.OAuthError> {
  const seen = new Set<string>();
  const extra: Record<string, string> = {};
  let count = 0;

  let state: string | undefined;
  let code: string | undefined;
  let error: string | undefined;
  let errorDescription: string | undefined;
  let errorUri: string | undefined;
  let issuer: string | undefined;
  let scope: string | undefined;

  for (const [key, value] of entries) {
    count += 1;
    if (count > maxCallbackParams) {
      return yield* callbackRejected("invalidParameters");
    }

    if (
      key.length === 0 ||
      key.length > 256 ||
      !V.isWellFormedUnicode(key) ||
      !V.isWellFormedUnicode(value)
    ) {
      return yield* callbackRejected("invalidParameters");
    }

    if (seen.has(key)) {
      return yield* callbackRejected("duplicateParameter");
    }
    seen.add(key);

    if (forbiddenCallbackParameters.has(key.toLowerCase())) {
      return yield* callbackRejected("unexpectedParameter");
    }

    const limit = key === "scope" ? maxCallbackScopeLength : maxCallbackValueLength;

    if (value.length > limit) {
      return yield* callbackRejected("invalidParameters");
    }

    if (standardCallbackParameters.has(key)) {
      switch (key) {
        case "state":
          state = value;
          break;
        case "code":
          code = value;
          break;
        case "error":
          error = value;
          break;
        case "error_description":
          errorDescription = value;
          break;
        case "error_uri":
          errorUri = value;
          break;
        case "iss":
          issuer = value;
          break;
        case "scope":
          scope = value;
          break;
      }
    } else if (options.allowed.has(key)) {
      defineExtraProperty(extra, key, value);
    } else if (options.unknownParameters === "reject") {
      return yield* callbackRejected("unexpectedParameter");
    }
  }

  if (state === undefined || state.length === 0) {
    return yield* callbackRejected("missingState");
  }

  if (issuer !== undefined && (issuer.length === 0 || issuer.length > 2048)) {
    return yield* callbackRejected("invalidParameters");
  }

  if ((code !== undefined) === (error !== undefined)) {
    return yield* callbackRejected("invalidParameters");
  }

  let outcome: CallbackOutcome;

  if (error !== undefined) {
    if (
      error.length === 0 ||
      error.length > 128 ||
      !authorizationErrorPattern.test(error) ||
      (errorUri !== undefined && errorUri.length > 2048)
    ) {
      return yield* callbackRejected("invalidParameters");
    }

    const normalized = V.normalizeOAuthErrorCode(error);

    outcome = Object.freeze({
      _tag: "Error" as const,
      code: normalized.code,
      ...(normalized.rawCode === undefined ? {} : { rawCode: normalized.rawCode }),
    });
  } else {
    if (
      code === undefined ||
      code.length === 0 ||
      !authorizationCodePattern.test(code) ||
      errorDescription !== undefined ||
      errorUri !== undefined
    ) {
      return yield* callbackRejected("invalidParameters");
    }

    outcome = Object.freeze({
      _tag: "Code" as const,
      code: Redacted.make(code),
      ...(scope === undefined ? {} : { scope }),
      extra: Object.freeze(extra),
    });
  }

  return Object.freeze({
    mode,
    state: Redacted.make(state),
    ...(issuer === undefined ? {} : { issuer }),
    outcome,
  });
});

/**
 * Decodes an OAuth 2.1 `query` authorization callback from a URL string,
 * `URL`-like `{ href }` object, or key-value iterable (`URLSearchParams`,
 * `UrlParams.UrlParams`).
 *
 * Enforces parameter count and value length bounds, rejects duplicate keys and
 * front-channel token parameters (`access_token`, `id_token`, `token`,
 * `token_type`, `expires_in`, `response`), requires non-empty `state` and
 * `code` XOR `error`, and redacts `state` and `code` immediately.
 *
 * @stability unstable
 * @category callbacks
 * @since 4.1.4
 */
export const callbackParamsFromQuery: (
  input:
    | string
    | { readonly href: string }
    | Iterable<readonly [string, string | Redacted.Redacted<string>]>,
  options?: CallbackDecodeOptions,
) => Effect.Effect<CallbackParams, OAuthError.OAuthError> = Effect.fnUntraced(function* (
  input:
    | string
    | { readonly href: string }
    | Iterable<readonly [string, string | Redacted.Redacted<string>]>,
  options?: CallbackDecodeOptions,
): Effect.fn.Return<CallbackParams, OAuthError.OAuthError> {
  const parsedOptions = yield* parseCallbackDecodeOptions(options);

  if (
    typeof input === "string" ||
    (Predicate.isObject(input) && "href" in input && typeof input.href === "string")
  ) {
    const [, url] = yield* extractCallbackUrl(input);

    yield* checkUrlEncodedBounds(url.search.startsWith("?") ? url.search.slice(1) : url.search);

    const entries: Array<readonly [string, string]> = [];

    for (const [key, value] of url.searchParams) {
      entries.push([key, value]);
    }

    return yield* decodeCallbackEntries("query", entries, parsedOptions);
  }

  if (Predicate.isObject(input) && Symbol.iterator in input) {
    const rawEntries = yield* Effect.try({
      try: () => {
        const collected: Array<readonly [unknown, unknown]> = [];
        const iterator = (input as Iterable<unknown>)[Symbol.iterator]();

        for (let step = iterator.next(); !step.done; step = iterator.next()) {
          if (collected.length >= maxCallbackParams) {
            return { _tag: "TooMany" as const };
          }
          if (!Array.isArray(step.value) || step.value.length !== 2) {
            return { _tag: "Malformed" as const };
          }
          collected.push([step.value[0], step.value[1]]);
        }

        return { _tag: "Entries" as const, entries: collected };
      },
      catch: () => V.invalidArgument("Invalid callback parameter iterable"),
    });

    if (rawEntries._tag === "TooMany") {
      return yield* callbackRejected("invalidParameters");
    }
    if (rawEntries._tag === "Malformed") {
      return yield* V.invalidArgument("Invalid callback parameter entry");
    }

    const entries: Array<readonly [string, string]> = [];

    for (const [key, value] of rawEntries.entries) {
      if (typeof key !== "string") {
        return yield* V.invalidArgument("Callback parameter key must be a string");
      }

      const revealed = yield* V.revealString(
        value as string | Redacted.Redacted<string>,
        () => V.invalidArgument("Callback parameter value is unavailable"),
        () => V.invalidArgument("Callback parameter value must be a string"),
      );

      entries.push([key, revealed]);
    }

    return yield* decodeCallbackEntries("query", entries, parsedOptions);
  }

  return yield* V.invalidArgument("Invalid query callback input");
});

/**
 * Decodes an OAuth 2.1 `form_post` authorization callback.
 *
 * Requires an empty URL query string, `application/x-www-form-urlencoded`
 * content type (UTF-8), and a UTF-8 body within `maxBytes` (default `16384`).
 * Applies the same parameter bounds, duplicate-key rejection, and front-channel
 * token rejection as {@link callbackParamsFromQuery}.
 *
 * @stability unstable
 * @category callbacks
 * @since 4.1.4
 */
export const callbackParamsFromFormPost: (
  options: CallbackDecodeOptions & {
    readonly url: string | { readonly href: string };
    readonly contentType: string | undefined;
    readonly body: Uint8Array | string;
    readonly maxBytes?: number | undefined;
  },
) => Effect.Effect<CallbackParams, OAuthError.OAuthError> = Effect.fnUntraced(function* (
  options: CallbackDecodeOptions & {
    readonly url: string | { readonly href: string };
    readonly contentType: string | undefined;
    readonly body: Uint8Array | string;
    readonly maxBytes?: number | undefined;
  },
): Effect.fn.Return<CallbackParams, OAuthError.OAuthError> {
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid form_post callback options");
  }

  const parsedOptions = yield* parseCallbackDecodeOptions(options);

  const maxBytes = yield* V.positiveInteger(
    "maxBytes",
    options.maxBytes ?? defaultMaxFormPostBytes,
  );

  if (maxBytes > defaultMaxResponseBytes) {
    return yield* V.invalidArgument(`maxBytes must not exceed ${defaultMaxResponseBytes} bytes`);
  }

  const [rawUrl, url] = yield* extractCallbackUrl(options.url);

  if (rawUrl.includes("?") || url.search !== "") {
    return yield* callbackRejected("invalidTransport");
  }

  if (!isFormUrlEncodedContentType(options.contentType)) {
    return yield* callbackRejected("invalidTransport");
  }

  let bodyText: string;

  if (options.body instanceof Uint8Array) {
    if (options.body.byteLength > maxBytes) {
      return yield* callbackRejected("invalidTransport");
    }

    bodyText = yield* Effect.try({
      try: () =>
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          options.body as Uint8Array,
        ),
      catch: () => callbackRejected("invalidTransport"),
    });
  } else if (typeof options.body === "string") {
    if (
      !V.isWellFormedUnicode(options.body) ||
      utf8Encoder.encode(options.body).byteLength > maxBytes
    ) {
      return yield* callbackRejected("invalidTransport");
    }
    bodyText = options.body;
  } else {
    return yield* V.invalidArgument("form_post body must be a string or Uint8Array");
  }

  const entries = yield* parseUrlEncodedString(bodyText);

  return yield* decodeCallbackEntries("form_post", entries, parsedOptions);
});

const copyCallbackExtra = Effect.fnUntraced(function* (
  extra: unknown,
): Effect.fn.Return<Readonly<Record<string, string>>, OAuthError.OAuthError> {
  if (extra === null || typeof extra !== "object" || Array.isArray(extra)) {
    return yield* V.invalidArgument("Invalid callback extra parameters");
  }

  const prototype = Object.getPrototypeOf(extra);

  if (prototype !== Object.prototype && prototype !== null) {
    return yield* V.invalidArgument("Invalid callback extra parameters");
  }

  const keys = Reflect.ownKeys(extra);

  if (keys.length > maxCallbackParams) {
    return yield* V.invalidArgument("Invalid callback extra parameters");
  }

  const target: Record<string, string> = {};

  for (const key of keys) {
    if (
      typeof key !== "string" ||
      key.length === 0 ||
      key.length > 256 ||
      !V.isWellFormedUnicode(key) ||
      forbiddenCallbackKeys.has(key) ||
      forbiddenCallbackParameters.has(key.toLowerCase())
    ) {
      return yield* V.invalidArgument("Invalid callback extra parameters");
    }

    const descriptor = Object.getOwnPropertyDescriptor(extra, key);

    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      typeof descriptor.value !== "string" ||
      descriptor.value.length > maxCallbackValueLength ||
      !V.isWellFormedUnicode(descriptor.value)
    ) {
      return yield* V.invalidArgument("Invalid callback extra parameters");
    }

    defineExtraProperty(target, key, descriptor.value);
  }

  return Object.freeze(target);
});

/**
 * Validates decoded {@link CallbackParams} against expected ceremony state
 * (accepting a {@link Transaction} directly).
 *
 * Enforces expiry, delivery `responseMode`, constant-time UTF-8 `state`
 * equality, and RFC 9207 `iss` verification in exact order for both `Code` and
 * `Error` outcomes before mapping bound `access_denied` errors to
 * `AuthorizationDenied` and all other bound errors to
 * `EndpointError({ endpoint: "authorization" })`.
 *
 * @stability unstable
 * @category callbacks
 * @since 4.1.4
 */
export const validateCallback: (
  callback: CallbackParams,
  expected: {
    readonly state: string | Redacted.Redacted<string>;
    readonly responseMode: ResponseMode;
    readonly issuer: string;
    readonly issuerIdentification: IssuerIdentificationMode;
    readonly expiresAt?: DateTime.Utc | undefined;
    readonly clockTolerance?: Duration.Input | undefined;
  },
) => Effect.Effect<CallbackResult, OAuthError.OAuthError> = Effect.fnUntraced(function* (
  callback: CallbackParams,
  expected: {
    readonly state: string | Redacted.Redacted<string>;
    readonly responseMode: ResponseMode;
    readonly issuer: string;
    readonly issuerIdentification: IssuerIdentificationMode;
    readonly expiresAt?: DateTime.Utc | undefined;
    readonly clockTolerance?: Duration.Input | undefined;
  },
): Effect.fn.Return<CallbackResult, OAuthError.OAuthError> {
  if (!Predicate.isObject(callback) || !Predicate.isObject(expected)) {
    return yield* V.invalidArgument("Invalid callback validation input");
  }

  const callbackMode = yield* V.configuration(
    ResponseModeSchema,
    callback.mode,
    "Invalid callback mode",
  );

  const callbackState = yield* decodeNonEmptySecret(
    callback.state,
    maxCallbackValueLength,
    "callback state",
    true,
  );

  const callbackIssuer =
    callback.issuer === undefined
      ? undefined
      : yield* V.configuration(V.text(2048), callback.issuer, "Invalid callback issuer");

  const expectedMode = yield* V.configuration(
    ResponseModeSchema,
    expected.responseMode,
    "Invalid expected responseMode",
  );

  const expectedState = yield* decodeNonEmptySecret(
    expected.state,
    maxCallbackValueLength,
    "expected state",
    true,
  );

  const expectedIssuer = yield* V.configuration(
    CallbackIssuer,
    expected.issuer,
    "Invalid expected issuer",
  );

  const issuerIdentification = yield* V.configuration(
    IssuerIdentificationSchema,
    expected.issuerIdentification,
    "Invalid issuerIdentification",
  );

  let expiresAtMillis: number | undefined;
  let clockToleranceMillis = 0;

  if (expected.clockTolerance !== undefined) {
    clockToleranceMillis = yield* V.finiteMillis("clockTolerance", expected.clockTolerance);
    if (clockToleranceMillis > maxCallbackClockToleranceMillis) {
      return yield* V.invalidArgument(
        `clockTolerance must not exceed ${maxCallbackClockToleranceMillis} milliseconds`,
      );
    }
  }

  if (expected.expiresAt !== undefined) {
    if (!DateTime.isDateTime(expected.expiresAt)) {
      return yield* V.invalidArgument("expected.expiresAt must be a DateTime.Utc");
    }
    const millis = DateTime.toEpochMillis(expected.expiresAt);

    if (!Number.isFinite(millis) || millis < 0) {
      return yield* V.invalidArgument("expected.expiresAt must be a non-negative instant");
    }
    expiresAtMillis = millis;
  }

  const outcome = callback.outcome;

  if (!Predicate.isObject(outcome)) {
    return yield* V.invalidArgument("Invalid callback outcome");
  }

  let validatedCode:
    | {
        readonly code: string;
        readonly scope: string | undefined;
        readonly extra: Readonly<Record<string, string>>;
      }
    | undefined;

  let validatedError:
    | {
        readonly code: OAuthError.OAuthErrorCode;
        readonly rawCode: string | undefined;
      }
    | undefined;

  if (outcome._tag === "Code") {
    const code = yield* decodeNonEmptySecret(
      outcome.code,
      maxCallbackValueLength,
      "authorization code",
      true,
    );

    if (!authorizationCodePattern.test(code)) {
      return yield* V.invalidArgument("Invalid authorization code");
    }

    const scope =
      outcome.scope === undefined
        ? undefined
        : yield* V.configuration(
            Schema.String.check(Schema.isMaxLength(maxCallbackScopeLength)),
            outcome.scope,
            "Invalid callback scope",
          );

    const extra = yield* copyCallbackExtra(outcome.extra);

    validatedCode = { code, scope, extra };
  } else if (outcome._tag === "Error") {
    if (typeof outcome.code !== "string" || !knownCallbackErrorCodes.has(outcome.code)) {
      return yield* V.invalidArgument("Invalid callback error code");
    }

    if (outcome.rawCode !== undefined) {
      if (
        outcome.code !== "other" ||
        typeof outcome.rawCode !== "string" ||
        outcome.rawCode.length === 0 ||
        outcome.rawCode.length > 128 ||
        !authorizationErrorPattern.test(outcome.rawCode)
      ) {
        return yield* V.invalidArgument("Invalid callback rawCode");
      }
    }

    validatedError = {
      code: outcome.code as OAuthError.OAuthErrorCode,
      rawCode: outcome.rawCode,
    };
  } else {
    return yield* V.invalidArgument("Invalid callback outcome");
  }

  // Normative check order for BOTH Code and Error outcomes (RFC 9207 §2.1 & §2.4, RFC 9700 §4.4.2):
  // 1. Transaction expiration and transport responseMode.
  if (expiresAtMillis !== undefined) {
    const nowMillis = yield* Clock.currentTimeMillis;

    if (nowMillis > expiresAtMillis + clockToleranceMillis) {
      return yield* callbackRejected("invalidTransport");
    }
  }

  if (callbackMode !== expectedMode) {
    return yield* callbackRejected("invalidTransport");
  }

  // 2. Constant-time UTF-8 state equality.
  if (!Mac.timingSafeEqual(utf8Encoder.encode(callbackState), utf8Encoder.encode(expectedState))) {
    return yield* callbackRejected("stateMismatch");
  }

  // 3. RFC 9207 iss verification.
  if (issuerIdentification === "required") {
    if (callbackIssuer === undefined) {
      return yield* callbackRejected("missingIssuer");
    }
    if (callbackIssuer !== expectedIssuer) {
      return yield* callbackRejected("issuerMismatch");
    }
  } else if (issuerIdentification === "unsupported") {
    if (callbackIssuer !== undefined) {
      return yield* callbackRejected("unexpectedParameter");
    }
  } else if (callbackIssuer !== undefined && callbackIssuer !== expectedIssuer) {
    return yield* callbackRejected("issuerMismatch");
  }

  // 4. Outcome classification after full ceremony binding succeeded.
  if (validatedError !== undefined) {
    if (validatedError.code === "access_denied") {
      return yield* new OAuthError.OAuthError({
        reason: new OAuthError.AuthorizationDenied(),
      });
    }

    return yield* new OAuthError.OAuthError({
      reason: new OAuthError.EndpointError({
        endpoint: "authorization",
        code: validatedError.code,
        ...(validatedError.rawCode === undefined ? {} : { rawCode: validatedError.rawCode }),
      }),
    });
  }

  if (validatedCode === undefined) {
    return yield* V.invalidArgument("Invalid callback outcome");
  }

  return Object.freeze({
    code: Redacted.make(validatedCode.code),
    ...(callbackIssuer === undefined ? {} : { issuer: callbackIssuer }),
    ...(validatedCode.scope === undefined ? {} : { scope: validatedCode.scope }),
    extra: validatedCode.extra,
  });
});
