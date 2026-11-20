/**
 * OAuth 2.1 token grants, raw private receipts, and bearer token-set parsing.
 *
 * Typed constructors ({@link authorizationCode}, {@link fromTransaction},
 * {@link refreshToken}, {@link clientCredentials}) build redacted grants and
 * reject reserved OAuth or client-authentication keys in `options.parameters`.
 * {@link make} constructs custom form grants while still reserving `grant_type`
 * and client-authentication parameters. {@link parseTokens} projects a
 * validated {@link TokenReceipt} into a {@link TokenSet} after any
 * provider-specific raw receipt inspection.
 *
 * @stability unstable
 * @since 4.1.4
 */
import * as Effect from "effect/Effect";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import * as Transport from "./internal/transport.ts";
import * as V from "./internal/validation.ts";
import * as OAuthError from "./OAuthError.ts";

const TypeId = "~effect/oauth/Grant" as const;

const clientAuthOwnedKeys: ReadonlySet<string> = new Set([
  "grant_type",
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
]);

/**
 * Schema for an uninterpreted private token-endpoint receipt.
 *
 * `body` uses `{ disallowJsonEncode: true }` so `Schema.toCodecJson` rejects
 * accidental plaintext serialization; use {@link TokenReceiptFromJson} for
 * encrypted receipt persistence (for example `Jwt.encrypt`).
 *
 * @stability unstable
 * @category schemas
 * @since 4.1.4
 */
export const TokenReceipt: Schema.Struct<{
  readonly status: Schema.Int;
  readonly contentType: Schema.NullOr<Schema.String>;
  readonly body: Schema.Redacted<Schema.$Record<Schema.String, Schema.Codec<Schema.Json>>>;
}> = Schema.Struct({
  status: V.integer(100, 599),
  contentType: Schema.NullOr(Schema.String.check(Schema.isMaxLength(512))),
  body: Schema.Redacted(V.JsonObject, { disallowJsonEncode: true }),
});

/**
 * An uninterpreted private token-endpoint receipt.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type TokenReceipt = typeof TokenReceipt.Type;

/**
 * Explicit storage codec for {@link TokenReceipt} using
 * `Schema.RedactedFromValue`. Use only when sealing receipts with
 * authenticated encryption (such as `Jwt.encrypt`).
 *
 * @stability unstable
 * @category schemas
 * @since 4.1.4
 */
export const TokenReceiptFromJson: Schema.Struct<{
  readonly status: Schema.Int;
  readonly contentType: Schema.NullOr<Schema.String>;
  readonly body: Schema.RedactedFromValue<Schema.$Record<Schema.String, Schema.Codec<Schema.Json>>>;
}> = Schema.Struct({
  status: V.integer(100, 599),
  contentType: Schema.NullOr(Schema.String.check(Schema.isMaxLength(512))),
  body: Schema.RedactedFromValue(V.JsonObject),
});

/**
 * Schema for a parsed OAuth 2.1 bearer token response.
 *
 * @stability unstable
 * @category schemas
 * @since 4.1.4
 */
export const TokenSet: Schema.Struct<{
  readonly tokenType: Schema.Literal<"bearer">;
  readonly accessToken: Schema.RedactedFromValue<Schema.String>;
  readonly refreshToken: Schema.optionalKey<Schema.RedactedFromValue<Schema.String>>;
  readonly idToken: Schema.optionalKey<Schema.RedactedFromValue<Schema.String>>;
  readonly expiresIn: Schema.optionalKey<Schema.Finite>;
  readonly scope: Schema.optionalKey<Schema.String>;
}> = Schema.Struct({
  tokenType: Schema.Literal("bearer"),
  accessToken: Schema.RedactedFromValue(V.text(16384)),
  refreshToken: Schema.optionalKey(Schema.RedactedFromValue(V.text(16384))),
  idToken: Schema.optionalKey(Schema.RedactedFromValue(V.text(65536))),
  expiresIn: Schema.optionalKey(Schema.Finite.check(Schema.isGreaterThanOrEqualTo(0))),
  scope: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16447))),
});

/**
 * A parsed OAuth 2.1 bearer token set with credentials kept in `Redacted`.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type TokenSet = typeof TokenSet.Type;

/**
 * A token-endpoint grant carrying `grantType`, ordered form `parameters`
 * (preserving repeated keys such as `resource`), and optional registration
 * bindings (`issuer`, `clientId`).
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface Grant {
  readonly [TypeId]: typeof TypeId;
  readonly grantType: string;
  readonly parameters: ReadonlyArray<readonly [string, string | Redacted.Redacted<string>]>;
  readonly issuer?: string | undefined;
  readonly clientId?: string | undefined;
}

/**
 * Validated, revealed grant parameters ready for form encoding.
 *
 * @internal
 */
export interface ResolvedGrant {
  readonly grantType: string;
  readonly parameters: ReadonlyArray<readonly [string, string]>;
  readonly issuer?: string | undefined;
  readonly clientId?: string | undefined;
}

const validators = new WeakMap<Grant, () => Effect.Effect<ResolvedGrant, OAuthError.OAuthError>>();

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

const invalidResponse = (status: number, description: string): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.InvalidResponse({ endpoint: "token", status, description }),
  });

const toRedacted = (value: string | Redacted.Redacted<string>): Redacted.Redacted<string> =>
  Redacted.isRedacted(value) ? value : Redacted.make(value);

const recordFromEntries = (
  entries: ReadonlyArray<readonly [string, string]>,
): Record<string, string> => {
  const target: Record<string, string> = {};

  for (const [key, value] of entries) {
    Object.defineProperty(target, key, {
      value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }

  return target;
};

const snapshotRecord = (
  record: Readonly<Record<string, string>> | undefined,
): ReadonlyArray<readonly [string, string]> | undefined => {
  if (record === undefined) return undefined;
  if (!Predicate.isObject(record)) return undefined;
  const entries: Array<readonly [string, string]> = [];

  for (const key of Object.keys(record)) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);

    if (descriptor === undefined || !("value" in descriptor)) continue;
    entries.push(Object.freeze([key, descriptor.value as string] as const));
  }

  return entries;
};

const snapshotStrings = (
  values: ReadonlyArray<string> | undefined,
): ReadonlyArray<string> | undefined => (Array.isArray(values) ? [...values] : undefined);

const buildGrant = (
  grantType: string,
  parameters: ReadonlyArray<readonly [string, string | Redacted.Redacted<string>]>,
  validate: () => Effect.Effect<ResolvedGrant, OAuthError.OAuthError>,
  binding?: { readonly issuer: string; readonly clientId: string },
): Grant => {
  const frozenParams = Object.freeze(parameters.map(([k, v]) => Object.freeze([k, v] as const)));

  const grant: Grant = Object.freeze({
    [TypeId]: TypeId,
    grantType,
    parameters: frozenParams,
    ...(binding === undefined ? {} : { issuer: binding.issuer, clientId: binding.clientId }),
  });

  validators.set(grant, validate);

  return grant;
};

const decodeSecretValue = (
  value: string | Redacted.Redacted<string>,
  maxLength: number,
  description: string,
): Effect.Effect<string, OAuthError.OAuthError> =>
  V.revealString(
    value,
    () => V.invalidArgument(`${description} is unavailable`),
    () => V.invalidArgument(`Invalid ${description}`),
  ).pipe(
    Effect.filterOrFail(
      (item) => item.length > 0 && item.length <= maxLength,
      () => V.invalidArgument(`Invalid ${description}`),
    ),
  );

const decodeExtraAndResources = Effect.fnUntraced(function* (
  parameters: unknown,
  resources: unknown,
): Effect.fn.Return<Array<readonly [string, string]>, OAuthError.OAuthError> {
  const out: Array<readonly [string, string]> = [];

  if (parameters !== undefined) {
    const validatedParams = yield* V.configuration(
      V.Parameters,
      parameters,
      "Invalid grant parameters",
    );

    for (const [key, value] of Object.entries(validatedParams)) {
      out.push([key, value]);
    }
  }

  if (resources !== undefined) {
    const validatedResources = yield* V.configuration(
      V.Resources,
      resources,
      "Invalid grant resources",
    );

    for (const resource of validatedResources) {
      out.push(["resource", resource]);
    }
  }

  return out;
});

const validateRawParameters = Effect.fnUntraced(function* (
  grantType: unknown,
  parameters: unknown,
): Effect.fn.Return<ResolvedGrant, OAuthError.OAuthError> {
  const validGrantType = yield* V.configuration(V.text(128), grantType, "Invalid grant_type");

  // oxlint-disable-next-line no-control-regex -- Reject control characters in grant_type.
  if (/[\r\n\u0000-\u001f\u007f]/u.test(validGrantType)) {
    return yield* V.invalidArgument("Invalid grant_type");
  }

  if (!Array.isArray(parameters)) {
    return yield* V.invalidArgument("Grant parameters must be an array of key-value pairs");
  }

  const out: Array<readonly [string, string]> = [];

  for (const entry of parameters) {
    if (!Array.isArray(entry) || entry.length !== 2) {
      return yield* V.invalidArgument("Invalid grant parameter entry");
    }

    const key: unknown = entry[0];
    const value: unknown = entry[1];

    if (
      typeof key !== "string" ||
      key.length === 0 ||
      key.length > 256 ||
      // oxlint-disable-next-line no-control-regex -- Reject control characters in form parameter names.
      /[\r\n\u0000-\u001f\u007f]/u.test(key)
    ) {
      return yield* V.invalidArgument("Invalid grant parameter key");
    }

    if (clientAuthOwnedKeys.has(key.toLowerCase())) {
      return yield* V.invalidArgument("Grant parameters cannot set grant_type or client auth keys");
    }

    const revealed = yield* V.revealString(
      value as string | Redacted.Redacted<string>,
      () => V.invalidArgument("Grant parameter value is unavailable"),
      () => V.invalidArgument("Invalid grant parameter value"),
    );

    out.push([key, revealed]);
  }

  return { grantType: validGrantType, parameters: out };
});

/**
 * Checks whether a value is a `Grant` created by this module.
 *
 * @internal
 */
export const isGrant = (u: unknown): u is Grant =>
  Predicate.isObject(u) && Predicate.hasProperty(u, TypeId) && validators.has(u as Grant);

/**
 * Validates and reveals a `Grant` before dispatch.
 *
 * @internal
 */
export const resolveGrant = (grant: Grant): Effect.Effect<ResolvedGrant, OAuthError.OAuthError> => {
  const validate = Predicate.isObject(grant) ? validators.get(grant) : undefined;

  return validate === undefined
    ? Effect.fail(V.invalidArgument("Invalid OAuth grant"))
    : validate();
};

/**
 * Constructs a custom form-encoded token grant.
 *
 * Raw grants reject `grant_type` and client-authentication keys (`client_id`,
 * `client_secret`, `client_assertion`, `client_assertion_type`), preserve
 * repeated parameter keys, and are bounded by the final encoded token request
 * body limit (`<= 131,072` UTF-8 bytes including client authentication fields).
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const make: (
  grantType: string,
  parameters: ReadonlyArray<readonly [string, string | Redacted.Redacted<string>]>,
) => Grant = (grantType, parameters) => {
  const copied = Array.isArray(parameters)
    ? parameters.map((entry) =>
        Array.isArray(entry) && entry.length === 2
          ? (Object.freeze([entry[0], entry[1]] as const) as readonly [
              string,
              string | Redacted.Redacted<string>,
            ])
          : entry,
      )
    : undefined;

  const grant: Grant = Object.freeze({
    [TypeId]: TypeId,
    grantType,
    parameters: Object.freeze(
      (copied ?? []).filter(
        (entry): entry is readonly [string, string | Redacted.Redacted<string>] =>
          Array.isArray(entry) && entry.length === 2,
      ),
    ),
  });

  validators.set(grant, () => validateRawParameters(grantType, copied));

  return grant;
};

/**
 * Parses a validated {@link TokenReceipt} into a bearer {@link TokenSet}.
 *
 * Inspect provider-specific receipt extensions before calling `parseTokens`.
 * `expires_in` accepts finite non-negative numbers and decimal strings without
 * whitespace or exponent syntax. A JSON `null` `refresh_token` is omitted, and
 * an array `scope` is joined with spaces.
 *
 * @stability unstable
 * @category parsing
 * @since 4.1.4
 */
export const parseTokens: (
  receipt: TokenReceipt,
) => Effect.Effect<TokenSet, OAuthError.OAuthError> = Effect.fnUntraced(function* (
  input: TokenReceipt,
): Effect.fn.Return<TokenSet, OAuthError.OAuthError> {
  const receipt = yield* V.decode(TokenReceipt, input, () =>
    V.invalidArgument("Invalid OAuth token receipt"),
  );

  if (!Transport.isJson(receipt.contentType)) {
    return yield* invalidResponse(receipt.status, "Expected application/json token receipt");
  }

  const raw = yield* V.reveal(receipt.body, () =>
    V.invalidArgument("Token receipt body is unavailable"),
  );

  if (Object.hasOwn(raw, "error")) {
    if (successFields.some((key) => Object.hasOwn(raw, key))) {
      return yield* invalidResponse(
        receipt.status,
        "Token error response must not include token fields",
      );
    }

    const terminal = yield* V.decode(Terminal, raw, () =>
      invalidResponse(receipt.status, "Invalid OAuth token error payload"),
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
      receipt.status,
      "Token error payload returned with non-4xx HTTP status",
    );
  }

  if (
    receipt.status !== 200 ||
    Object.hasOwn(raw, "error_description") ||
    Object.hasOwn(raw, "error_uri")
  ) {
    return yield* invalidResponse(receipt.status, "Unexpected OAuth token response");
  }

  const value = yield* V.decode(RawToken, raw, () =>
    invalidResponse(receipt.status, "Invalid OAuth token response payload"),
  );

  const scope: string | undefined =
    typeof value.scope === "string"
      ? value.scope
      : value.scope === undefined
        ? undefined
        : value.scope.join(" ");

  if (scope !== undefined && scope.length > 16447) {
    return yield* invalidResponse(receipt.status, "Token scope exceeds maximum length");
  }

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

/**
 * Constructs an `authorization_code` grant. `redirectUri` is optional for
 * providers (such as Strava) that omit `redirect_uri` on token exchange; prefer
 * {@link fromTransaction} when redeeming a stored `OAuth.Transaction`.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const authorizationCode: (options: {
  readonly code: string | Redacted.Redacted<string>;
  readonly redirectUri?: string | undefined;
  readonly pkceVerifier?: string | Redacted.Redacted<string> | undefined;
  readonly resources?: ReadonlyArray<string> | undefined;
  readonly parameters?: Readonly<Record<string, string>> | undefined;
}) => Grant = (options) => {
  const validObject = Predicate.isObject(options);
  const rawParameters = validObject ? options.parameters : undefined;
  const rawResources = validObject ? options.resources : undefined;
  const paramEntries = snapshotRecord(rawParameters);
  const resourceSnapshot = snapshotStrings(rawResources);
  const code = validObject ? options.code : undefined;
  const redirectUri = validObject ? options.redirectUri : undefined;
  const pkceVerifier = validObject ? options.pkceVerifier : undefined;

  const entries: Array<readonly [string, string | Redacted.Redacted<string>]> = [];

  if (paramEntries !== undefined) entries.push(...paramEntries);
  if (resourceSnapshot !== undefined) {
    for (const resource of resourceSnapshot) entries.push(["resource", resource]);
  }
  if (code !== undefined) {
    entries.push(["code", toRedacted(code)]);
  }
  if (pkceVerifier !== undefined) {
    entries.push(["code_verifier", toRedacted(pkceVerifier)]);
  }
  if (redirectUri !== undefined) {
    entries.push(["redirect_uri", redirectUri]);
  }

  return buildGrant(
    "authorization_code",
    entries,
    Effect.fnUntraced(function* () {
      if (!validObject) {
        return yield* V.invalidArgument("Invalid authorization code grant input");
      }

      const out = yield* decodeExtraAndResources(
        rawParameters === undefined
          ? undefined
          : paramEntries === undefined
            ? rawParameters
            : recordFromEntries(paramEntries),
        rawResources === undefined ? undefined : (resourceSnapshot ?? rawResources),
      );

      const revealedCode = yield* decodeSecretValue(
        code as string | Redacted.Redacted<string>,
        16384,
        "authorization code",
      );

      out.push(["code", revealedCode]);

      if (pkceVerifier !== undefined) {
        const revealedVerifier = yield* V.revealString(
          pkceVerifier,
          () => V.invalidArgument("PKCE verifier is unavailable"),
          () => V.invalidArgument("Invalid PKCE verifier"),
        );

        yield* V.configuration(
          V.Verifier,
          Redacted.make(revealedVerifier),
          "Invalid PKCE verifier",
        );
        out.push(["code_verifier", revealedVerifier]);
      }

      if (redirectUri !== undefined) {
        const validRedirectUri = yield* V.configuration(
          V.Callback,
          redirectUri,
          "Invalid redirectUri",
        );

        out.push(["redirect_uri", validRedirectUri]);
      }

      return { grantType: "authorization_code", parameters: out };
    }),
  );
};

/**
 * Constructs an `authorization_code` grant bound to a stored transaction's
 * `issuer`, `clientId`, `redirectUri`, optional `pkceVerifier`, and optional
 * `resources`. `OAuth.Client` verifies `issuer` and `clientId` before sending
 * the code.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const fromTransaction: (
  code: string | Redacted.Redacted<string>,
  transaction: {
    readonly issuer: string;
    readonly clientId: string;
    readonly redirectUri: string;
    readonly pkceVerifier?: Redacted.Redacted<string> | undefined;
    readonly resources?: ReadonlyArray<string> | undefined;
  },
  options?: { readonly parameters?: Readonly<Record<string, string>> | undefined },
) => Grant = (code, transaction, options) => {
  const validTransaction = Predicate.isObject(transaction);
  const validOptions = options === undefined || Predicate.isObject(options);
  const rawParameters = validOptions ? options?.parameters : options;
  const rawResources = validTransaction ? transaction.resources : undefined;
  const paramEntries = validOptions ? snapshotRecord(options?.parameters) : undefined;
  const resourceSnapshot = snapshotStrings(rawResources);
  const issuer = validTransaction ? transaction.issuer : "";
  const clientId = validTransaction ? transaction.clientId : "";
  const redirectUri = validTransaction ? transaction.redirectUri : undefined;
  const pkceVerifier = validTransaction ? transaction.pkceVerifier : undefined;

  const entries: Array<readonly [string, string | Redacted.Redacted<string>]> = [];

  if (paramEntries !== undefined) entries.push(...paramEntries);
  if (resourceSnapshot !== undefined) {
    for (const resource of resourceSnapshot) entries.push(["resource", resource]);
  }
  entries.push(["code", toRedacted(code)]);
  if (pkceVerifier !== undefined) {
    entries.push(["code_verifier", toRedacted(pkceVerifier)]);
  }
  if (redirectUri !== undefined) {
    entries.push(["redirect_uri", redirectUri]);
  }

  return buildGrant(
    "authorization_code",
    entries,
    Effect.fnUntraced(function* () {
      if (!validTransaction || !validOptions) {
        return yield* V.invalidArgument("Invalid authorization transaction grant input");
      }

      const validIssuer = yield* V.configuration(V.Issuer, issuer, "Invalid transaction issuer");

      const validClientId = yield* V.configuration(
        V.text(1024),
        clientId,
        "Invalid transaction clientId",
      );

      const validRedirectUri = yield* V.configuration(
        V.Callback,
        redirectUri,
        "Invalid transaction redirectUri",
      );

      const out = yield* decodeExtraAndResources(
        rawParameters === undefined
          ? undefined
          : paramEntries === undefined
            ? rawParameters
            : recordFromEntries(paramEntries),
        rawResources === undefined ? undefined : (resourceSnapshot ?? rawResources),
      );

      const revealedCode = yield* decodeSecretValue(code, 16384, "authorization code");

      out.push(["code", revealedCode]);

      if (pkceVerifier !== undefined) {
        const revealedVerifier = yield* V.revealString(
          pkceVerifier,
          () => V.invalidArgument("PKCE verifier is unavailable"),
          () => V.invalidArgument("Invalid PKCE verifier"),
        );

        yield* V.configuration(
          V.Verifier,
          Redacted.make(revealedVerifier),
          "Invalid PKCE verifier",
        );
        out.push(["code_verifier", revealedVerifier]);
      }

      out.push(["redirect_uri", validRedirectUri]);

      return {
        grantType: "authorization_code",
        parameters: out,
        issuer: validIssuer,
        clientId: validClientId,
      };
    }),
    validTransaction ? { issuer, clientId } : undefined,
  );
};

/**
 * Constructs a `refresh_token` grant with optional narrowed `scopes`,
 * `resources`, and extra `parameters`.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const refreshToken: (options: {
  readonly refreshToken: string | Redacted.Redacted<string>;
  readonly scopes?: ReadonlyArray<string> | undefined;
  readonly resources?: ReadonlyArray<string> | undefined;
  readonly parameters?: Readonly<Record<string, string>> | undefined;
}) => Grant = (options) => {
  const validObject = Predicate.isObject(options);
  const rawParameters = validObject ? options.parameters : undefined;
  const rawResources = validObject ? options.resources : undefined;
  const rawScopes = validObject ? options.scopes : undefined;
  const paramEntries = snapshotRecord(rawParameters);
  const resourceSnapshot = snapshotStrings(rawResources);
  const scopeSnapshot = snapshotStrings(rawScopes);
  const token = validObject ? options.refreshToken : undefined;

  const entries: Array<readonly [string, string | Redacted.Redacted<string>]> = [];

  if (paramEntries !== undefined) entries.push(...paramEntries);
  if (resourceSnapshot !== undefined) {
    for (const resource of resourceSnapshot) entries.push(["resource", resource]);
  }
  if (token !== undefined) {
    entries.push(["refresh_token", toRedacted(token)]);
  }
  if (scopeSnapshot !== undefined && scopeSnapshot.length > 0) {
    entries.push(["scope", scopeSnapshot.join(" ")]);
  }

  return buildGrant(
    "refresh_token",
    entries,
    Effect.fnUntraced(function* () {
      if (!validObject) {
        return yield* V.invalidArgument("Invalid refresh token grant input");
      }

      const out = yield* decodeExtraAndResources(
        rawParameters === undefined
          ? undefined
          : paramEntries === undefined
            ? rawParameters
            : recordFromEntries(paramEntries),
        rawResources === undefined ? undefined : (resourceSnapshot ?? rawResources),
      );

      const revealedToken = yield* decodeSecretValue(
        token as string | Redacted.Redacted<string>,
        16384,
        "refresh token",
      );

      out.push(["refresh_token", revealedToken]);

      if (rawScopes !== undefined) {
        const validScopes = yield* V.configuration(
          V.Scopes,
          scopeSnapshot ?? rawScopes,
          "Invalid refresh token scopes",
        );

        if (validScopes.length > 0) {
          out.push(["scope", validScopes.join(" ")]);
        }
      }

      return { grantType: "refresh_token", parameters: out };
    }),
  );
};

/**
 * Constructs a `client_credentials` grant with optional `scopes`, `resources`,
 * and extra `parameters`.
 *
 * `OAuth.Client` rejects `client_credentials` when authenticated with
 * `ClientAuth.none` unless `allowUnauthenticatedClientCredentials: true` is
 * configured for mutual-TLS transports (RFC 6749 §4.4).
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const clientCredentials: (options?: {
  readonly scopes?: ReadonlyArray<string> | undefined;
  readonly resources?: ReadonlyArray<string> | undefined;
  readonly parameters?: Readonly<Record<string, string>> | undefined;
}) => Grant = (options) => {
  const validObject = options === undefined || Predicate.isObject(options);
  const rawParameters = validObject ? options?.parameters : undefined;
  const rawResources = validObject ? options?.resources : undefined;
  const rawScopes = validObject ? options?.scopes : undefined;
  const paramEntries = snapshotRecord(rawParameters);
  const resourceSnapshot = snapshotStrings(rawResources);
  const scopeSnapshot = snapshotStrings(rawScopes);

  const entries: Array<readonly [string, string | Redacted.Redacted<string>]> = [];

  if (paramEntries !== undefined) entries.push(...paramEntries);
  if (resourceSnapshot !== undefined) {
    for (const resource of resourceSnapshot) entries.push(["resource", resource]);
  }
  if (scopeSnapshot !== undefined && scopeSnapshot.length > 0) {
    entries.push(["scope", scopeSnapshot.join(" ")]);
  }

  return buildGrant(
    "client_credentials",
    entries,
    Effect.fnUntraced(function* () {
      if (!validObject) {
        return yield* V.invalidArgument("Invalid client credentials grant input");
      }

      const out = yield* decodeExtraAndResources(
        rawParameters === undefined
          ? undefined
          : paramEntries === undefined
            ? rawParameters
            : recordFromEntries(paramEntries),
        rawResources === undefined ? undefined : (resourceSnapshot ?? rawResources),
      );

      if (rawScopes !== undefined) {
        const validScopes = yield* V.configuration(
          V.Scopes,
          scopeSnapshot ?? rawScopes,
          "Invalid client credentials scopes",
        );

        if (validScopes.length > 0) {
          out.push(["scope", validScopes.join(" ")]);
        }
      }

      return { grantType: "client_credentials", parameters: out };
    }),
  );
};
