import { Effect, Schema } from "effect";

import {
  OAuthConnectedProtectionContext,
  OAuthConnectedSealedTokens,
  OAuthConnectedTokenMaterial,
} from "../connectedModels";
import type { OAuthConnectedTokenKeyring } from "../OAuthConnectedTokenProtector";
import { OAuthUnavailable } from "../signInErrors";
import { OAuthEncryptionKeyId } from "../signInModels";
import { snapshotOAuthSync } from "../signInSnapshot";
import { payloadEncryption } from "./payload";

const contextCodec = Schema.fromJsonString(
  Schema.Tuple([
    Schema.Literal("effect-auth/oauth-connected-token-aead/v1"),
    OAuthConnectedSealedTokens.fields.format,
    OAuthEncryptionKeyId,
    OAuthConnectedProtectionContext,
  ]),
);

const encoder = new TextEncoder();

const validate = (context: OAuthConnectedProtectionContext, input: OAuthConnectedTokenMaterial) => {
  const material = snapshotOAuthSync(OAuthConnectedTokenMaterial, input);

  const token =
    context.namespace === "effect-auth/oauth-connected-token-context/v1" ? context : context.token;

  if (
    (token.configuration.protocol === "oidc") !== (material.continuation._tag === "Oidc") ||
    (token.configuration.profile.retention === "access-only" && material.refreshToken !== undefined)
  )
    throw OAuthUnavailable.make({});

  return material;
};

const aad = (context: OAuthConnectedProtectionContext, keyId: string) => {
  const json = Schema.encodeSync(contextCodec)([
    "effect-auth/oauth-connected-token-aead/v1",
    "oauth-connected-xchacha20poly1305-v1",
    keyId,
    context,
  ]);

  if (json.length > 262144) throw OAuthUnavailable.make({});
  const bytes = encoder.encode(json);

  if (bytes.length > 262144) {
    bytes.fill(0);
    throw OAuthUnavailable.make({});
  }

  return bytes;
};

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
