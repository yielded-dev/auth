import type * as Discovery from "@yielded/oauth/Discovery";
import * as OAuth from "@yielded/oauth/OAuth";
import type * as OAuthError from "@yielded/oauth/OAuthError";
import type * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import type * as Digest from "effect/crypto/Digest";
import type * as SecureRandom from "effect/crypto/SecureRandom";
import type * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import type * as HttpClient from "effect/http/HttpClient";
import type * as Jwk from "effect/jose/Jwk";
import type * as Jwks from "effect/jose/Jwks";
import type * as Scope from "effect/Scope";

import { makeEmailEnrichment } from "../github/email";
import { classifyOAuthConfigurationError } from "./classifyOAuthError";
import { makeAuthenticatedTokenSender, type AuthenticatedTokenSender } from "./http";
import { makeProfileFetch, type ProfileFetcher } from "./profileFetch";

/** Provider construction captures explicit platform/crypto services within its Scope. */
export type Requirements =
  | (SecureRandom.SecureRandom | Digest.Digest)
  | HttpClient.HttpClient
  | Scope.Scope;

export interface NativeKeySet {
  readonly jwks: Jwks.Jwks["Service"];
  readonly algorithms: ReadonlyArray<Jwk.AsymmetricAlgorithm>;
  readonly issuerPolicy?: Oidc.IssuerPolicy | undefined;
  readonly signature: Signature.Signature["Service"];
  readonly digest: Digest.Digest["Service"];
}

export interface NativeVendorOptions {
  readonly githubVerifiedPrimaryEmail?: boolean;
  readonly profile?: {
    readonly url: string;
    readonly method?: "GET" | "POST";
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: string;
  };
  readonly tokenBodyFormat?: "form" | "json";
  readonly scopeSeparator?: " " | ",";
  readonly supportsRefresh?: boolean;
}

export interface NativeProvider {
  readonly client: OAuth.Client;
  readonly fetchProfile?: ProfileFetcher;
  readonly codeTokenSender?: AuthenticatedTokenSender["codeGrant"];
  readonly refreshTokenSender?: AuthenticatedTokenSender["refreshGrant"];
  readonly enrichIdentity?: Effect.Success<ReturnType<typeof makeEmailEnrichment>>;
  readonly verifier?: Oidc.Verifier["Service"];
  readonly nativeKeySet?: NativeKeySet;
  readonly discovery?: Discovery.Discovery["Service"];
  readonly http?: HttpClient.HttpClient;
}

export const install = Effect.fn("OpenIdConnect.installNative")(function* (
  options: OAuth.ClientOptions,
  vendor?: NativeVendorOptions,
) {
  const mapConfigError = <A, R>(effect: Effect.Effect<A, OAuthError.OAuthError, R>) =>
    effect.pipe(
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

  const client = yield* mapConfigError(OAuth.make(options));

  const fetchProfile =
    vendor?.profile === undefined
      ? undefined
      : yield* mapConfigError(
          makeProfileFetch({
            issuer: options.metadata.issuer,
            ...vendor.profile,
            timeoutMs: options.timeoutMs,
            ...(options.maxResponseBytes === undefined
              ? {}
              : { maxResponseBytes: options.maxResponseBytes }),
          }),
        );

  const useJsonTokens = vendor?.tokenBodyFormat === "json";
  const useCommaRefresh = vendor?.scopeSeparator === "," && vendor?.supportsRefresh === true;

  const tokenSender =
    useJsonTokens || useCommaRefresh
      ? yield* mapConfigError(
          makeAuthenticatedTokenSender({
            issuer: options.metadata.issuer,
            tokenEndpoint: options.metadata.token_endpoint,
            clientId: options.clientId,
            authentication: options.authentication,
            timeoutMs: options.timeoutMs,
            ...(options.maxResponseBytes === undefined
              ? {}
              : { maxResponseBytes: options.maxResponseBytes }),
            ...(vendor?.tokenBodyFormat === undefined
              ? {}
              : { tokenBodyFormat: vendor.tokenBodyFormat }),
            ...(vendor?.scopeSeparator === undefined
              ? {}
              : { scopeSeparator: vendor.scopeSeparator }),
          }),
        )
      : undefined;

  return {
    client,
    ...(fetchProfile === undefined ? {} : { fetchProfile }),
    ...(useJsonTokens && tokenSender !== undefined
      ? { codeTokenSender: tokenSender.codeGrant }
      : {}),
    ...(vendor?.supportsRefresh === true && tokenSender !== undefined
      ? { refreshTokenSender: tokenSender.refreshGrant }
      : {}),
    ...(vendor?.githubVerifiedPrimaryEmail === true
      ? { enrichIdentity: yield* makeEmailEnrichment(options.timeoutMs) }
      : {}),
  };
});
