import { Effect, Schema } from "effect";

import {
  OAuthConnectedProtectionContext,
  OAuthConnectedSealedTokens,
  OAuthConnectedTokenMaterial,
} from "../connectedModels";
import type { OAuthConnectedTokenKeyring } from "../OAuthConnectedTokenProtector";
import { OAuthUnavailable } from "../signInErrors";
import { OAuthEncryptionKeyId } from "../signInModels";
import { encodeUtf8, payloadEncryption } from "./payload";

const contextCodec = Schema.fromJsonString(
  Schema.Tuple([
    Schema.Literal("effect-auth/oauth-connected-token-aead/v1"),
    OAuthConnectedSealedTokens.fields.format,
    OAuthEncryptionKeyId,
    OAuthConnectedProtectionContext,
  ]),
);

const validate = Effect.fnUntraced(function* (
  context: OAuthConnectedProtectionContext,
  material: OAuthConnectedTokenMaterial,
) {
  const token =
    context.namespace === "effect-auth/oauth-connected-token-context/v1" ? context : context.token;

  if (
    (token.configuration.protocol === "oidc") !== (material.continuation._tag === "Oidc") ||
    (token.configuration.profile.retention === "access-only" && material.refreshToken !== undefined)
  )
    return yield* OAuthUnavailable.make({});

  return material;
});

const aad = Effect.fnUntraced(function* (context: OAuthConnectedProtectionContext, keyId: string) {
  const json = yield* Schema.encodeEffect(contextCodec)([
    "effect-auth/oauth-connected-token-aead/v1",
    "oauth-connected-xchacha20poly1305-v1",
    keyId,
    context,
  ]).pipe(Effect.mapError(() => OAuthUnavailable.make({})));

  return yield* encodeUtf8(json, 262144);
});

export const make = (keyring: OAuthConnectedTokenKeyring) =>
  payloadEncryption(
    {
      context: OAuthConnectedProtectionContext,
      plaintext: OAuthConnectedTokenMaterial,
      envelope: OAuthConnectedSealedTokens,
      format: "oauth-connected-xchacha20poly1305-v1",
      maximumPlaintextBytes: 98304,
      aad,
      validate,
    },
    keyring,
  ).pipe(
    Effect.map((encryption) => ({
      seal: (input: {
        readonly context: OAuthConnectedProtectionContext;
        readonly material: OAuthConnectedTokenMaterial;
      }) => encryption.seal(input.context, input.material),
      open: (input: {
        readonly context: OAuthConnectedProtectionContext;
        readonly sealed: OAuthConnectedSealedTokens;
      }) => encryption.open(input.context, input.sealed),
    })),
  );
