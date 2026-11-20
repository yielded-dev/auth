import type * as Discovery from "@yielded/oauth/Discovery";
import * as OAuth from "@yielded/oauth/OAuth";
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

export interface NativeProvider {
  readonly client: OAuth.Client;
  readonly enrichIdentity?: Effect.Success<ReturnType<typeof makeEmailEnrichment>>;
  readonly verifier?: Oidc.Verifier["Service"];
  readonly nativeKeySet?: NativeKeySet;
  readonly discovery?: Discovery.Discovery["Service"];
  readonly http?: HttpClient.HttpClient;
}

export const install = Effect.fn("OpenIdConnect.installNative")(function* (
  options: OAuth.ClientOptions,
  githubVerifiedPrimaryEmail = false,
) {
  const client = yield* OAuth.make(options).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(Cause.map(cause, classifyOAuthConfigurationError)),
    ),
  );

  return {
    client,
    ...(githubVerifiedPrimaryEmail
      ? { enrichIdentity: yield* makeEmailEnrichment(options.timeoutMs) }
      : {}),
  };
});
