import type * as ClientAuth from "@yielded/oauth/ClientAuth";
import * as Discovery from "@yielded/oauth/Discovery";
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
import { makeJsonTokenSender, type JsonTokenSender } from "./http";
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

export interface NativeInstallOptions {
  readonly metadata: Discovery.Metadata;
  readonly clientId: string;
  readonly clientAuth: ClientAuth.Method<never>;
  readonly revocationAuth?: ClientAuth.Method<never>;
  readonly timeoutMs: number;
  readonly maxResponseBytes?: number;
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
}

export interface NativeProvider {
  readonly client: OAuth.Client["Service"];
  readonly fetchProfile?: ProfileFetcher;
  readonly jsonTokenSender?: JsonTokenSender;
  readonly enrichIdentity?: Effect.Success<ReturnType<typeof makeEmailEnrichment>>;
  readonly verifier?: Oidc.Verifier["Service"];
  readonly nativeKeySet?: NativeKeySet;
  readonly discovery?: Discovery.Discovery["Service"];
  readonly http?: HttpClient.HttpClient;
}

export const install = Effect.fn("OpenIdConnect.installNative")(function* (
  options: NativeInstallOptions,
  vendor?: NativeVendorOptions,
) {
  const mapConfigError = <A, R>(effect: Effect.Effect<A, OAuthError.OAuthError, R>) =>
    effect.pipe(
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
      ),
    );

  const localDiscovery = yield* mapConfigError(Discovery.makeLocal(options.metadata));

  const client = yield* mapConfigError(
    OAuth.make({
      clientId: options.clientId,
      clientAuth: options.clientAuth,
      ...(options.revocationAuth === undefined ? {} : { revocationAuth: options.revocationAuth }),
      timeout: options.timeoutMs,
      ...(options.maxResponseBytes === undefined
        ? {}
        : { maxResponseBytes: options.maxResponseBytes }),
    }).pipe(Effect.provideService(Discovery.Discovery, localDiscovery)),
  );

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

  const jsonTokenSender =
    vendor?.tokenBodyFormat === "json"
      ? yield* mapConfigError(
          makeJsonTokenSender({
            issuer: options.metadata.issuer,
            tokenEndpoint: options.metadata.token_endpoint,
            clientId: options.clientId,
            clientAuth: options.clientAuth,
            timeoutMs: options.timeoutMs,
            ...(options.maxResponseBytes === undefined
              ? {}
              : { maxResponseBytes: options.maxResponseBytes }),
            ...(vendor.scopeSeparator === undefined
              ? {}
              : { scopeSeparator: vendor.scopeSeparator }),
          }),
        )
      : undefined;

  return {
    client,
    ...(fetchProfile === undefined ? {} : { fetchProfile }),
    ...(jsonTokenSender === undefined ? {} : { jsonTokenSender }),
    ...(vendor?.githubVerifiedPrimaryEmail === true
      ? { enrichIdentity: yield* makeEmailEnrichment(options.timeoutMs) }
      : {}),
  };
});
