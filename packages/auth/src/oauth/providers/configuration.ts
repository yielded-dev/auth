import type * as OAuth from "@yielded/oauth/OAuth";
import * as Oidc from "@yielded/oauth/Oidc";
import { Effect, Predicate, Redacted, Schema } from "effect";

import { OAuthProviderKey, OAuthGeneration } from "../schema";
import { OAuthUnavailable } from "../signInErrors";
import {
  OAuthAuthorizationUrl,
  OAuthCallbackId,
  OAuthIssuer,
  OAuthRedirectUri,
} from "../signInModels";
import { freezeOAuth } from "../signInSnapshot";
import { TokenCompatibility, tokenCompatibility } from "./compatibility";
import {
  OpenIdConnectConfigurationError,
  type OpenIdConnectOAuthProvider,
  type OpenIdConnectOAuthProtocolOptions,
  type OpenIdConnectOidcProvider,
} from "./models";
import { install, type NativeProvider } from "./native";

const boundedString = (maximum: number) =>
  Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(maximum));

const fields = Schema.Record(
  Schema.String.check(Schema.isPattern(/^[A-Za-z][A-Za-z0-9._~-]{0,63}$/)),
  Schema.String.check(Schema.isMaxLength(2048)),
).check(Schema.makeFilter((record) => Object.keys(record).length <= 16));

const secret = Schema.RedactedFromValue(boundedString(4096));

export const authentication = Schema.Union([
  Schema.Struct({ method: Schema.Literal("client_secret_basic"), secret }),
  Schema.Struct({ method: Schema.Literal("client_secret_post"), secret }),
  Schema.Struct({ method: Schema.Literal("none"), publicClient: Schema.Literal(true) }),
]);

const common = {
  provider: OAuthProviderKey,
  configurationGeneration: OAuthGeneration,
  issuance: Schema.Literals(["active", "retired"]),
  issuer: OAuthIssuer,
  responseIssuerMode: Schema.Literals(["required", "unsupported"]),
  clientId: boundedString(1024),
  authentication,
  callbacks: Schema.Array(
    Schema.Struct({ callbackId: OAuthCallbackId, redirectUri: OAuthRedirectUri }),
  ).check(Schema.isMinLength(1), Schema.isMaxLength(16)),
  scopes: Schema.Array(
    Schema.String.check(Schema.isPattern(/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/)),
  ).check(Schema.isMaxLength(32)),
  authorizationParameters: Schema.optionalKey(fields),
  tokenParameters: Schema.optionalKey(fields),
};

const optionsSchema = <R>() =>
  Schema.toType(
    Schema.Struct({
      providers: Schema.Array(
        Schema.Union([
          Schema.Struct({
            ...common,
            protocol: Schema.Literal("oidc"),
            idTokenSignedResponseAlg: Schema.Literal("RS256"),
            maxAgeSeconds: Schema.optionalKey(
              Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 86400 })),
            ),
          }),
          Schema.Struct({
            ...common,
            protocol: Schema.Literal("oauth"),
            [tokenCompatibility]: Schema.optionalKey(TokenCompatibility),
            authorizationEndpoint: boundedString(2048),
            tokenEndpoint: boundedString(2048),
            pkceS256: Schema.Literal(true),
            identitySource: Schema.Struct({
              url: boundedString(2048),
              headers: Schema.optionalKey(fields),
              // A configured function is trusted application code; its result has a separate schema boundary.
              decodeIdentity: Schema.declare<
                OpenIdConnectOAuthProvider<R>["identitySource"]["decodeIdentity"]
              >(
                (
                  input,
                ): input is OpenIdConnectOAuthProvider<R>["identitySource"]["decodeIdentity"] =>
                  Predicate.isFunction(input),
              ),
            }),
          }),
        ]),
      ).check(Schema.isMinLength(1), Schema.isMaxLength(64)),
      timeoutSeconds: Schema.Finite.check(Schema.isBetween({ minimum: 1, maximum: 30 })),
    }),
  );

const reserved = new Set([
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

const forbiddenHeaders = new Set([
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
]);

const configError = (reason: OpenIdConnectConfigurationError["reason"]) =>
  OpenIdConnectConfigurationError.make({ reason });

const protocolUrl = (value: string, allowLoopback: boolean): URL => {
  const url = new URL(value);

  if (
    (url.protocol !== "https:" &&
      !(
        allowLoopback &&
        url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
      )) ||
    url.username !== "" ||
    url.password !== "" ||
    value.includes("#") ||
    // oxlint-disable-next-line no-control-regex -- Reject ambiguous protocol URL control characters.
    /[\s\\\u0000-\u001f\u007f]/u.test(value)
  )
    throw configError("metadata");

  return url;
};

/** Provider endpoints always require HTTPS. */
export const endpoint = (value: string): URL => protocolUrl(value, false);

/** Local development callbacks may use HTTP on an exact loopback host. */
export const callbackEndpoint = (value: string): URL => protocolUrl(value, true);

const checkParameters = (parameters: Readonly<Record<string, string>> | undefined) => {
  for (const key of Object.keys(parameters ?? {})) {
    if (reserved.has(key.toLowerCase())) throw configError("parameters");
  }
};

export type Provider<R> = OpenIdConnectOidcProvider | OpenIdConnectOAuthProvider<R>;

export interface InstalledProvider<R> extends NativeProvider {
  readonly provider: Provider<R>;
  readonly metadata: OAuth.Metadata;
}

const metadataSchema = Schema.Struct({
  issuer: OAuthIssuer,
  authorization_endpoint: boundedString(2048),
  token_endpoint: boundedString(2048),
  jwks_uri: Schema.optionalKey(boundedString(2048)),
  code_challenge_methods_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  response_types_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  id_token_signing_alg_values_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  token_endpoint_auth_methods_supported: Schema.optionalKey(Schema.Array(boundedString(64))),
  authorization_response_iss_parameter_supported: Schema.optionalKey(Schema.Boolean),
});

export const installConfigurations = Effect.fn("OpenIdConnect.installConfigurations")(function* <R>(
  input: OpenIdConnectOAuthProtocolOptions<R>,
) {
  const options = yield* Schema.decodeEffect(optionsSchema<R>())(input).pipe(
    Effect.mapError(() => configError("provider")),
  );

  // Detach secrets as well as arrays and records before retaining configuration.
  const providers = options.providers.map((provider): Provider<R> => {
    const detached = {
      callbacks: provider.callbacks.map((callback) => ({ ...callback })),
      scopes: [...provider.scopes],
      ...(provider.authorizationParameters === undefined
        ? {}
        : { authorizationParameters: { ...provider.authorizationParameters } }),
      ...(provider.tokenParameters === undefined
        ? {}
        : { tokenParameters: { ...provider.tokenParameters } }),
      authentication:
        provider.authentication.method === "none"
          ? { ...provider.authentication }
          : {
              ...provider.authentication,
              secret: Redacted.make(Redacted.value(provider.authentication.secret)),
            },
    };

    return provider.protocol === "oidc"
      ? { ...provider, ...detached }
      : {
          ...provider,
          ...detached,
          identitySource: {
            ...provider.identitySource,
            ...(provider.identitySource.headers === undefined
              ? {}
              : { headers: { ...provider.identitySource.headers } }),
          },
        };
  });

  yield* Effect.try({
    try: () => {
      const generations = new Set<string>();
      const active = new Set<string>();
      const names = new Set<string>();

      for (const provider of providers) {
        const generation = `${provider.provider.length}:${provider.provider}:${provider.configurationGeneration}`;

        if (generations.has(generation)) throw configError("generation");
        generations.add(generation);
        names.add(provider.provider);
        if (provider.issuance === "active") {
          if (active.has(provider.provider)) throw configError("generation");
          active.add(provider.provider);
        }
        const issuer = endpoint(provider.issuer);

        if (provider.issuer.includes("?") || issuer.pathname.includes("/.well-known/"))
          throw configError("issuer");
        if (new Set(provider.scopes).size !== provider.scopes.length)
          throw configError("parameters");
        if ((provider.protocol === "oidc") !== provider.scopes.includes("openid"))
          throw configError("parameters");
        checkParameters(provider.authorizationParameters);
        checkParameters(provider.tokenParameters);
        const callbacks = new Set<string>();

        for (const callback of provider.callbacks) {
          const url = callbackEndpoint(callback.redirectUri);

          if (
            url.href !== callback.redirectUri ||
            callback.redirectUri.includes("?") ||
            callbacks.has(callback.callbackId)
          )
            throw configError("callback");
          callbacks.add(callback.callbackId);
          for (const other of providers) {
            if (provider.issuer === other.issuer) continue;
            if (
              provider.responseIssuerMode === "required" &&
              other.responseIssuerMode === "required"
            )
              continue;
            if (other.callbacks.some((candidate) => candidate.redirectUri === callback.redirectUri))
              throw configError("callback");
          }
        }
        if (provider.protocol === "oauth") {
          endpoint(provider.identitySource.url);
          for (const key of Object.keys(provider.identitySource.headers ?? {})) {
            if (forbiddenHeaders.has(key.toLowerCase())) throw configError("identity-source");
          }
          new Headers(provider.identitySource.headers);
        }
        freezeOAuth(provider);
      }
      if (active.size !== names.size) throw configError("generation");
    },
    catch: (error) =>
      Schema.is(OpenIdConnectConfigurationError)(error) ? error : configError("provider"),
  });
  const installed: InstalledProvider<R>[] = [];

  for (const provider of providers) {
    let raw: OAuth.Metadata;

    if (provider.protocol === "oidc") {
      raw = yield* Oidc.discover(provider.issuer, {
        timeoutMs: options.timeoutSeconds * 1000,
      }).pipe(
        Effect.mapError((error) =>
          error._tag === "OAuthConfigurationError"
            ? configError("metadata")
            : OAuthUnavailable.make({}),
        ),
      );
    } else {
      raw = {
        issuer: provider.issuer,
        authorization_endpoint: provider.authorizationEndpoint,
        token_endpoint: provider.tokenEndpoint,
        authorization_response_iss_parameter_supported: provider.responseIssuerMode === "required",
      };
    }

    // oxlint-disable-next-line no-restricted-properties -- Discovered foreign metadata is not yet validated for this adapter profile.
    const metadata = yield* Schema.decodeUnknownEffect(metadataSchema)(raw).pipe(
      Effect.mapError(() => configError("metadata")),
    );

    yield* Effect.try({
      try: () => {
        if (metadata.issuer !== provider.issuer) throw configError("issuer");
        if (
          (metadata.authorization_response_iss_parameter_supported === true) !==
          (provider.responseIssuerMode === "required")
        )
          throw configError("metadata");
        const auth = endpoint(metadata.authorization_endpoint);

        for (const key of auth.searchParams.keys()) {
          if (reserved.has(key.toLowerCase())) throw configError("parameters");
        }
        endpoint(metadata.token_endpoint);

        const supportedAuthentication =
          metadata.token_endpoint_auth_methods_supported ??
          (provider.protocol === "oidc" ? ["client_secret_basic"] : undefined);

        if (
          supportedAuthentication !== undefined &&
          !supportedAuthentication.includes(provider.authentication.method)
        )
          throw configError("authentication");

        if (provider.protocol === "oidc") {
          if (
            !metadata.code_challenge_methods_supported?.includes("S256") ||
            !metadata.response_types_supported?.includes("code") ||
            !metadata.id_token_signing_alg_values_supported?.includes("RS256") ||
            metadata.jwks_uri === undefined
          )
            throw configError("metadata");
          endpoint(metadata.jwks_uri);
        } else {
          endpoint(provider.identitySource.url);
        }
        freezeOAuth(metadata);
      },
      catch: (error) =>
        Schema.is(OpenIdConnectConfigurationError)(error) ? error : configError("metadata"),
    });

    const native = yield* install(
      {
        metadata,
        clientId: provider.clientId,
        authentication: provider.authentication,
        timeoutMs: options.timeoutSeconds * 1000,
        ...(provider.protocol === "oauth" ? { profile: provider.identitySource } : {}),
      },
      provider.protocol === "oidc",
    );

    const placeholder = Redacted.make("a".repeat(43));

    for (const callback of provider.callbacks) {
      const url = yield* native.client
        .authorizationUrl({
          redirectUri: callback.redirectUri,
          scopes: provider.scopes,
          state: placeholder,
          codeChallenge: Redacted.value(placeholder),
          ...(provider.authorizationParameters === undefined
            ? {}
            : { parameters: provider.authorizationParameters }),
          ...(provider.protocol === "oidc"
            ? {
                nonce: placeholder,
                ...(provider.maxAgeSeconds === undefined
                  ? {}
                  : { maxAgeSeconds: provider.maxAgeSeconds }),
              }
            : {}),
        })
        .pipe(Effect.mapError(() => configError("parameters")));

      yield* Schema.decodeEffect(OAuthAuthorizationUrl)(Redacted.value(url)).pipe(
        Effect.mapError(() => configError("parameters")),
      );
    }
    installed.push({ provider, metadata, ...native });
  }

  return { installed, timeoutSeconds: options.timeoutSeconds };
});
