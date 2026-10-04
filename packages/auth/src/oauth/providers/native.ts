import type { Hmac } from "@yielded/crypto/Hmac";
import type { Signature } from "@yielded/crypto/Signature";
import * as OAuth from "@yielded/oauth/OAuth";
import * as Oidc from "@yielded/oauth/Oidc";
import { type Crypto, Effect, type Redacted, type Scope } from "effect";
import type { HttpClient } from "effect/http";

import { OAuthUnavailable } from "../signInErrors";
import { OpenIdConnectConfigurationError } from "./models";

/** Provider construction captures explicit platform/crypto services within its Scope. */
export type Requirements = Crypto.Crypto | Hmac | Signature | HttpClient.HttpClient | Scope.Scope;

export interface NativeProvider {
  readonly client: OAuth.Client;
  readonly verifier?: {
    readonly verify: (
      token: Redacted.Redacted<string>,
      input: Oidc.VerificationInput,
    ) => Effect.Effect<Oidc.Verified, Effect.Error<ReturnType<Oidc.Verifier["verify"]>>>;
  };
}

export const install = Effect.fn("OpenIdConnect.installNative")(function* (
  options: OAuth.ClientOptions,
  oidc: boolean,
) {
  const client = yield* OAuth.make(options).pipe(
    Effect.mapError((error) =>
      error._tag === "OAuthConfigurationError"
        ? OpenIdConnectConfigurationError.make({ reason: "metadata" })
        : OAuthUnavailable.make({}),
    ),
  );

  if (!oidc) return { client };
  const context = yield* Effect.context<Crypto.Crypto | Hmac | Signature>();

  const verifier = yield* Oidc.makeVerifier(options).pipe(
    Effect.mapError((error) =>
      error._tag === "OAuthConfigurationError"
        ? OpenIdConnectConfigurationError.make({ reason: "metadata" })
        : OAuthUnavailable.make({}),
    ),
  );

  return {
    client,
    verifier: {
      verify: (token: Redacted.Redacted<string>, input: Oidc.VerificationInput) =>
        verifier.verify(token, input).pipe(Effect.provideContext(context)),
    },
  };
});
