import { Context, type Effect, Layer, Schema } from "effect";

import { OAuthLinkTransactionContext } from "./accountsModels";
import { OAuthUnavailable } from "./signInErrors";
import type { OAuthTransactionSecrets } from "./signInModels";
import { OAuthEncryptionKeyId, OAuthSealedTransaction } from "./signInModels";
import { snapshotOAuthSync } from "./signInSnapshot";
import { transactionEncryption, type OAuthTransactionKeyring } from "./transactionEncryption";

const codec = Schema.fromJsonString(
  Schema.Tuple([
    Schema.Literal("effect-auth/oauth-link-aead/v1"),
    OAuthSealedTransaction.fields.format,
    OAuthEncryptionKeyId,
    OAuthLinkTransactionContext,
  ]),
);

const encoder = new TextEncoder();

const aad = (context: OAuthLinkTransactionContext, keyId: string) => {
  const value = Schema.encodeSync(codec)([
    "effect-auth/oauth-link-aead/v1",
    "oauth-xchacha20poly1305-v1",
    keyId,
    snapshotOAuthSync(OAuthLinkTransactionContext, context),
  ]);

  if (value.length > 16384) throw OAuthUnavailable.make({});
  const bytes = encoder.encode(value);

  if (bytes.length > 16384) {
    bytes.fill(0);
    throw OAuthUnavailable.make({});
  }

  return bytes;
};

/** Typed authenticated-link domain, isolated from guest sign-in. Dedicated keyring
 * retention covers issued and claimed link horizons and deployment convergence;
 * link-binder signing keys have their own independent retention obligation. */
export class OAuthLinkTransactionProtector extends Context.Service<
  OAuthLinkTransactionProtector,
  {
    readonly seal: (input: {
      readonly context: OAuthLinkTransactionContext;
      readonly secrets: OAuthTransactionSecrets;
    }) => Effect.Effect<OAuthSealedTransaction, OAuthUnavailable>;
    readonly open: (input: {
      readonly context: OAuthLinkTransactionContext;
      readonly sealed: OAuthSealedTransaction;
    }) => Effect.Effect<OAuthTransactionSecrets, OAuthUnavailable>;
  }
>()("effect-auth/OAuthLinkTransactionProtector") {
  static readonly xchacha20poly1305 = (keyring: OAuthTransactionKeyring) =>
    Layer.effect(this, transactionEncryption(OAuthLinkTransactionContext, aad, keyring));
}
