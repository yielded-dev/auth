import { Context, type Effect, Layer, Schema } from "effect";

import { OAuthConnectedTransactionContext } from "./connectedModels";
import { OAuthUnavailable } from "./signInErrors";
import type { OAuthTransactionSecrets } from "./signInModels";
import { OAuthSealedTransaction } from "./signInModels";
import { snapshotOAuthSync } from "./signInSnapshot";
import { transactionEncryption, type OAuthTransactionKeyring } from "./transactionEncryption";

const codec = Schema.fromJsonString(
  Schema.Tuple([
    Schema.Literal("effect-auth/oauth-connected-aead/v1"),
    OAuthSealedTransaction.fields.format,
    OAuthSealedTransaction.fields.keyId,
    OAuthConnectedTransactionContext,
  ]),
);

const encoder = new TextEncoder();

const aad = (context: OAuthConnectedTransactionContext, keyId: string) => {
  const value = Schema.encodeSync(codec)([
    "effect-auth/oauth-connected-aead/v1",
    "oauth-xchacha20poly1305-v1",
    keyId,
    snapshotOAuthSync(OAuthConnectedTransactionContext, context),
  ]);

  if (value.length > 262144) throw OAuthUnavailable.make({});
  const bytes = encoder.encode(value);

  if (bytes.length > 262144) {
    bytes.fill(0);
    throw OAuthUnavailable.make({});
  }

  return bytes;
};

/** Separate connected purpose. Key retention includes original claim horizons. */
export class OAuthConnectedTransactionProtector extends Context.Service<
  OAuthConnectedTransactionProtector,
  {
    readonly seal: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly secrets: OAuthTransactionSecrets;
    }) => Effect.Effect<OAuthSealedTransaction, OAuthUnavailable>;
    readonly open: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly sealed: OAuthSealedTransaction;
    }) => Effect.Effect<OAuthTransactionSecrets, OAuthUnavailable>;
  }
>()("effect-auth/OAuthConnectedTransactionProtector") {
  static readonly xchacha20poly1305 = (keyring: OAuthTransactionKeyring) =>
    Layer.effect(this, transactionEncryption(OAuthConnectedTransactionContext, aad, keyring));
}
