/**
 * Authorization-server metadata schemas and the `Discovery` service that
 * resolves metadata locally or from remote well-known endpoints.
 *
 * {@link makeLocal} and {@link layerLocal} validate and serve fixed metadata.
 * {@link makeRemote} and {@link layerRemote} lazily fetch and cache a remote
 * discovery document for the owning `Scope`, coalescing concurrent callers and
 * enforcing HTTPS/loopback anti-downgrade rules.
 *
 * @stability unstable
 * @since 4.1.4
 */
import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Deferred from "effect/Deferred";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import type * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Predicate from "effect/Predicate";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import * as Transport from "./internal/transport.ts";
import * as V from "./internal/validation.ts";
import * as OAuthError from "./OAuthError.ts";

/**
 * Schema for OAuth 2.0 / OpenID Connect authorization-server metadata
 * (RFC 8414 / OpenID Connect Discovery 1.0), preserving unknown JSON extension
 * members while enforcing HTTPS and loopback endpoint rules.
 *
 * HTTP loopback endpoints (`localhost`, `127.0.0.1`, `[::1]`) are accepted only
 * when `issuer` itself is an HTTP loopback URL.
 *
 * @stability unstable
 * @category schemas
 * @since 4.1.4
 */
export const Metadata: Schema.StructWithRest<
  Schema.Struct<{
    readonly issuer: Schema.String;
    readonly authorization_endpoint: Schema.optionalKey<Schema.String>;
    readonly token_endpoint: Schema.String;
    readonly jwks_uri: Schema.optionalKey<Schema.String>;
    readonly userinfo_endpoint: Schema.optionalKey<Schema.String>;
    readonly revocation_endpoint: Schema.optionalKey<Schema.String>;
    readonly code_challenge_methods_supported: Schema.optionalKey<Schema.$Array<Schema.String>>;
    readonly response_types_supported: Schema.optionalKey<Schema.$Array<Schema.String>>;
    readonly grant_types_supported: Schema.optionalKey<Schema.$Array<Schema.String>>;
    readonly id_token_signing_alg_values_supported: Schema.optionalKey<
      Schema.$Array<Schema.String>
    >;
    readonly token_endpoint_auth_methods_supported: Schema.optionalKey<
      Schema.$Array<Schema.String>
    >;
    readonly revocation_endpoint_auth_methods_supported: Schema.optionalKey<
      Schema.$Array<Schema.String>
    >;
    readonly authorization_response_iss_parameter_supported: Schema.optionalKey<Schema.Boolean>;
  }>,
  readonly [Schema.$Record<Schema.String, Schema.Codec<Schema.Json>>]
> = Schema.StructWithRest(
  Schema.Struct({
    issuer: V.Issuer,
    authorization_endpoint: Schema.optionalKey(V.ProtocolEndpoint),
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
  }),
  [Schema.Record(Schema.String, Schema.Json)],
).check(
  Schema.makeFilter(
    (metadata) =>
      V.hasSafeJsonGraph(metadata) &&
      endpointsOf(metadata).every((endpoint) => V.endpointMatchesIssuer(metadata.issuer, endpoint)),
  ),
);

/**
 * Validated authorization-server discovery metadata.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type Metadata = typeof Metadata.Type;

/**
 * Service that resolves validated authorization-server metadata.
 *
 * @stability unstable
 * @category services
 * @since 4.1.4
 */
export class Discovery extends Context.Service<
  Discovery,
  {
    readonly resolve: Effect.Effect<Metadata, OAuthError.OAuthError>;
  }
>()("effect/oauth/Discovery") {}

/**
 * Options for {@link makeRemote} and {@link layerRemote}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface RemoteOptions {
  /**
   * Trusted issuer identifier used to derive the default well-known URL and
   * verify the discovered document's `issuer`.
   */
  readonly issuer: string;
  /**
   * Explicit metadata document URL overriding well-known derivation. Must
   * satisfy the issuer's HTTPS/loopback scheme constraint.
   */
  readonly url?: string | undefined;
  /**
   * Well-known discovery document profile used when `url` is omitted.
   * Defaults to `"openid-configuration"` (OIDC Discovery 1.0 §4.1).
   * `"oauth-authorization-server"` follows RFC 8414 §3.1 path insertion.
   */
  readonly wellKnown?: "openid-configuration" | "oauth-authorization-server" | undefined;
  /**
   * Cache lifetime for a fetched document. Defaults to `"Infinity"` (scope lifetime).
   */
  readonly timeToLive?: Duration.Input | undefined;
  /**
   * Minimum time before retrying after a failed fetch. Defaults to `"30 seconds"`.
   */
  readonly cooldown?: Duration.Input | undefined;
  /**
   * Timeout for the discovery request and reading its body. Defaults to `"5 seconds"`.
   */
  readonly timeout?: Duration.Input | undefined;
  /**
   * Maximum discovery response body size in bytes. Defaults to `131072` (128 KiB).
   */
  readonly maxResponseBytes?: number | undefined;
  /**
   * Custom issuer matcher validating `discoveredIssuer` against
   * `configuredIssuer` and returning the canonical accepted issuer string.
   * Defaults to exact equality (`discoveredIssuer === configuredIssuer`).
   */
  readonly issuerMatcher?:
    | ((
        configuredIssuer: string,
        discoveredIssuer: string,
      ) => Effect.Effect<string, OAuthError.OAuthError>)
    | undefined;
  /**
   * Optional post-normalization metadata supplement hook. Receives a copy whose
   * `issuer` is already normalized to the accepted issuer; the returned
   * document is unconditionally re-validated to preserve that issuer and
   * endpoint scheme constraints.
   */
  readonly supplement?:
    | ((metadata: Metadata) => Effect.Effect<Metadata, OAuthError.OAuthError>)
    | undefined;
}

interface Snapshot {
  readonly metadata: Metadata;
  readonly expiresAt: number;
}

const endpointsOf = (metadata: {
  readonly authorization_endpoint?: string | undefined;
  readonly token_endpoint: string;
  readonly jwks_uri?: string | undefined;
  readonly userinfo_endpoint?: string | undefined;
  readonly revocation_endpoint?: string | undefined;
}): ReadonlyArray<string> =>
  [
    metadata.authorization_endpoint,
    metadata.token_endpoint,
    metadata.jwks_uri,
    metadata.userinfo_endpoint,
    metadata.revocation_endpoint,
  ].filter((endpoint): endpoint is string => endpoint !== undefined);

const discoveryFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.DiscoveryFailed({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const transportFailed = (
  description: string,
  options?: { readonly status?: number | undefined; readonly cause?: unknown },
): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.TransportFailed({
      endpoint: "discovery",
      description,
      ...(options?.status === undefined ? {} : { status: options.status }),
      ...(options?.cause === undefined ? {} : { cause: options.cause }),
    }),
  });

// `Duration` reads NaN as zero in every input form, and non-finite or
// overflowing object components add up to NaN. Reject them eagerly.
const hasInvalidDurationComponent = (input: Duration.Input): boolean => {
  if (typeof input === "number") return Number.isNaN(input);
  if (typeof input !== "object" || input === null || Duration.isDuration(input)) return false;
  if (Array.isArray(input)) return input.some((component) => !Number.isFinite(component));

  return Object.entries(input).some(
    ([unit, component]) =>
      typeof component === "number" &&
      (!Number.isFinite(component) || !Number.isFinite(Duration.toMillis({ [unit]: component }))),
  );
};

const durationMillis = (input: Duration.Input): Option.Option<number> =>
  hasInvalidDurationComponent(input)
    ? Option.none()
    : Option.map(Duration.fromInput(input), Duration.toMillis);

const finiteMillis = (
  name: string,
  input: Duration.Input,
): Effect.Effect<number, OAuthError.OAuthError> => {
  const value = durationMillis(input);

  return Option.isSome(value) && Number.isFinite(value.value) && value.value >= 0
    ? Effect.succeed(value.value)
    : Effect.fail(V.invalidArgument(`${name} must be a finite, non-negative duration`));
};

const positiveFiniteMillis = (
  name: string,
  input: Duration.Input,
): Effect.Effect<number, OAuthError.OAuthError> => {
  const value = durationMillis(input);

  return Option.isSome(value) && Number.isFinite(value.value) && value.value > 0
    ? Effect.succeed(value.value)
    : Effect.fail(V.invalidArgument(`${name} must be a finite, positive duration`));
};

const positiveMillisOrInfinity = (
  name: string,
  input: Duration.Input,
): Effect.Effect<number, OAuthError.OAuthError> => {
  const value = durationMillis(input);

  return Option.isSome(value) && !Number.isNaN(value.value) && value.value > 0
    ? Effect.succeed(value.value)
    : Effect.fail(V.invalidArgument(`${name} must be a positive duration or Infinity`));
};

const positiveInteger = (
  name: string,
  value: number,
): Effect.Effect<number, OAuthError.OAuthError> =>
  Number.isSafeInteger(value) && value > 0
    ? Effect.succeed(value)
    : Effect.fail(V.invalidArgument(`${name} must be a positive integer`));

const buildWellKnownUrl = (
  issuer: string,
  wellKnown: "openid-configuration" | "oauth-authorization-server",
): string => {
  const url = new URL(issuer);
  const trimmedPath = url.pathname.replace(/\/$/u, "");

  url.pathname =
    wellKnown === "oauth-authorization-server"
      ? `/.well-known/oauth-authorization-server${trimmedPath}`
      : `${trimmedPath}/.well-known/openid-configuration`;

  return url.href;
};

/**
 * Builds a `Discovery` service for fixed, pre-validated metadata.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const makeLocal: (
  metadata: Metadata,
) => Effect.Effect<Discovery["Service"], OAuthError.OAuthError> = (metadata) =>
  V.snapshotPlainJson(metadata, () => V.invalidArgument("Invalid OAuth discovery metadata")).pipe(
    Effect.flatMap((snapshot) =>
      V.decode(Metadata, snapshot, () => V.invalidArgument("Invalid OAuth discovery metadata")),
    ),
    Effect.map((validated) => {
      const frozen = V.freeze(validated);

      return Discovery.of({
        resolve: Effect.succeed(frozen),
      });
    }),
  );

/**
 * Layer that provides `Discovery` for fixed metadata validated by {@link makeLocal}.
 *
 * @stability unstable
 * @category layers
 * @since 4.1.4
 */
export const layerLocal: (metadata: Metadata) => Layer.Layer<Discovery, OAuthError.OAuthError> = (
  metadata,
) => Layer.effect(Discovery, makeLocal(metadata));

/**
 * Builds a lazy, scoped `Discovery` service backed by a remote well-known
 * metadata endpoint.
 *
 * Options are validated eagerly with zero network I/O during construction. The
 * first `resolve` fetches the metadata document, coalescing concurrent callers
 * into one in-flight request attached to the owning `Scope`. Closing the scope
 * interrupts any in-flight request and fails later resolutions with
 * `TransportFailed`.
 *
 * **Gotchas**
 *
 * Supply an `HttpClient` without retries or automatic redirects. HTTP loopback
 * endpoints and explicit discovery URLs are permitted only when `options.issuer`
 * itself is an explicitly configured HTTP loopback URL; applications accepting
 * untrusted issuer strings must enforce HTTPS at their policy boundary.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const makeRemote: (
  options: RemoteOptions,
) => Effect.Effect<
  Discovery["Service"],
  OAuthError.OAuthError,
  HttpClient.HttpClient | Scope.Scope
> = Effect.fnUntraced(function* (
  options: RemoteOptions,
): Effect.fn.Return<
  Discovery["Service"],
  OAuthError.OAuthError,
  HttpClient.HttpClient | Scope.Scope
> {
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid discovery options");
  }

  const configuredIssuer = yield* V.configuration(
    V.Issuer,
    options.issuer,
    "Invalid discovery issuer",
  );

  const wellKnown = options.wellKnown ?? "openid-configuration";

  if (wellKnown !== "openid-configuration" && wellKnown !== "oauth-authorization-server") {
    return yield* V.invalidArgument(
      'wellKnown must be "openid-configuration" or "oauth-authorization-server"',
    );
  }

  let requestUrl: string;

  if (options.url !== undefined) {
    const explicitUrl = yield* V.configuration(V.Endpoint, options.url, "Invalid discovery URL");

    if (!V.endpointMatchesIssuer(configuredIssuer, explicitUrl)) {
      return yield* V.invalidArgument("Discovery URL scheme does not match configured issuer");
    }

    requestUrl = new URL(explicitUrl).href;
  } else {
    requestUrl = buildWellKnownUrl(configuredIssuer, wellKnown);
  }

  const timeToLive = yield* positiveMillisOrInfinity(
    "timeToLive",
    options.timeToLive ?? Duration.infinity,
  );

  const cooldown = yield* finiteMillis("cooldown", options.cooldown ?? "30 seconds");
  const timeoutMs = yield* positiveFiniteMillis("timeout", options.timeout ?? "5 seconds");

  const maxResponseBytes = yield* positiveInteger(
    "maxResponseBytes",
    options.maxResponseBytes ?? 131072,
  );

  if (options.issuerMatcher !== undefined && !Predicate.isFunction(options.issuerMatcher)) {
    return yield* V.invalidArgument("issuerMatcher must be a function");
  }

  if (options.supplement !== undefined && !Predicate.isFunction(options.supplement)) {
    return yield* V.invalidArgument("supplement must be a function");
  }

  const issuerMatcher = options.issuerMatcher;
  const supplement = options.supplement;
  const http = yield* Transport.capture;
  const scope = yield* Effect.scope;

  let cache: Snapshot | undefined;
  let pending: Deferred.Deferred<Snapshot, OAuthError.OAuthError> | undefined;
  let lastAttempt = -Infinity;
  let lastFailed = false;
  let closed = false;

  const closedExit = Exit.fail(transportFailed("The discovery scope is closed"));

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      closed = true;
      if (pending !== undefined) Deferred.doneUnsafe(pending, closedExit);
    }),
  );

  const fetchDocument: Effect.Effect<Snapshot, OAuthError.OAuthError> = Effect.gen(function* () {
    const response = yield* Transport.request(
      http,
      HttpClientRequest.get(requestUrl).pipe(HttpClientRequest.acceptJson),
      { timeoutMs, maxResponseBytes },
      "discovery",
    );

    if (response.status !== 200) {
      return yield* transportFailed("Unexpected discovery response status", {
        status: response.status,
      });
    }

    const document = yield* Transport.json(response, "discovery");

    const body = yield* V.reveal(document.body, () =>
      transportFailed("Discovery response body is unavailable", { status: response.status }),
    );

    const rawMetadata = yield* V.decode(Metadata, body, () =>
      discoveryFailed("Invalid OAuth discovery metadata"),
    );

    const acceptedIssuer =
      issuerMatcher === undefined
        ? rawMetadata.issuer === configuredIssuer
          ? configuredIssuer
          : yield* discoveryFailed("Discovered issuer does not match configured issuer")
        : yield* issuerMatcher(configuredIssuer, rawMetadata.issuer);

    const validatedIssuer = yield* V.decode(V.Issuer, acceptedIssuer, () =>
      discoveryFailed("Accepted discovery issuer is invalid"),
    );

    if (!V.endpointMatchesIssuer(configuredIssuer, validatedIssuer)) {
      return yield* discoveryFailed(
        "Accepted discovery issuer scheme does not match configured issuer",
      );
    }

    const normalized = yield* V.decode(Metadata, { ...rawMetadata, issuer: validatedIssuer }, () =>
      discoveryFailed("Normalized OAuth discovery metadata is invalid"),
    );

    const validated =
      supplement === undefined
        ? normalized
        : yield* supplement(normalized).pipe(
            Effect.flatMap((supplemented) =>
              V.snapshotPlainJson(supplemented, () =>
                discoveryFailed("Supplemented OAuth discovery metadata is invalid"),
              ),
            ),
            Effect.flatMap((snapshot) =>
              V.decode(Metadata, snapshot, () =>
                discoveryFailed("Supplemented OAuth discovery metadata is invalid"),
              ),
            ),
          );

    if (validated.issuer !== validatedIssuer) {
      return yield* discoveryFailed(
        "Supplemented discovery metadata must preserve the accepted issuer",
      );
    }

    if (
      !endpointsOf(validated).every((endpoint) =>
        V.endpointMatchesIssuer(configuredIssuer, endpoint),
      )
    ) {
      return yield* discoveryFailed(
        "Discovery metadata endpoint scheme does not match configured issuer",
      );
    }

    const now = yield* Clock.currentTimeMillis;

    return {
      metadata: V.freeze(validated),
      expiresAt: now + timeToLive,
    };
  });

  const refresh = (now: number): Effect.Effect<Snapshot, OAuthError.OAuthError> =>
    Effect.uninterruptibleMask((restore) =>
      Effect.suspend((): Effect.Effect<Snapshot, OAuthError.OAuthError> => {
        if (closed) return closedExit;
        if (cache !== undefined && cache.expiresAt > now) return Effect.succeed(cache);
        if (pending !== undefined) return restore(Deferred.await(pending));
        if (lastFailed && now - lastAttempt < cooldown) {
          return Effect.fail(transportFailed("Discovery is cooling down after a failed fetch"));
        }

        lastAttempt = now;
        const result = (pending = Deferred.makeUnsafe<Snapshot, OAuthError.OAuthError>());

        return fetchDocument.pipe(
          Effect.onExit((exit) =>
            Effect.sync(() => {
              pending = undefined;
              lastFailed = Exit.isFailure(exit);
              if (Exit.isSuccess(exit)) cache = exit.value;
              Deferred.doneUnsafe(
                result,
                Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause) ? closedExit : exit,
              );
            }),
          ),
          Effect.forkIn(scope, { uninterruptible: false }),
          Effect.andThen(restore(Deferred.await(result))),
        );
      }),
    );

  const resolve: Effect.Effect<Metadata, OAuthError.OAuthError> = Effect.flatMap(
    Clock.currentTimeMillis,
    (now) => {
      if (closed) return closedExit;
      if (cache !== undefined && cache.expiresAt > now) return Effect.succeed(cache.metadata);

      return Effect.map(refresh(now), (snapshot) => snapshot.metadata);
    },
  );

  return Discovery.of({ resolve });
});

/**
 * Layer that provides `Discovery` from a remote metadata endpoint built by
 * {@link makeRemote}. Closing the layer interrupts any request in flight.
 *
 * @stability unstable
 * @category layers
 * @since 4.1.4
 */
export const layerRemote: (
  options: RemoteOptions,
) => Layer.Layer<Discovery, OAuthError.OAuthError, HttpClient.HttpClient> = (options) =>
  Layer.effect(Discovery, makeRemote(options));
