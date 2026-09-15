import { Context, type Effect, Layer, Schema } from "effect";

import { OAuthUnavailable } from "./signInErrors";
import type { OAuthTransactionSecrets } from "./signInModels";
import {
  OAuthEncryptionKeyId,
  OAuthSealedTransaction,
  OAuthSignInTransactionContext,
} from "./signInModels";
import { snapshotOAuthSync } from "./signInSnapshot";
import { transactionEncryption, type OAuthTransactionKeyring } from "./transactionEncryption";
export type { OAuthTransactionKeyring } from "./transactionEncryption";
const c = OAuthSignInTransactionContext.fields;

const aadCodec = Schema.fromJsonString(
  Schema.Tuple([
    Schema.Literal("effect-auth/oauth-sign-in-aead/v1"),
    OAuthSealedTransaction.fields.format,
    OAuthEncryptionKeyId,
    c.namespace,
    c.moduleId,
    c.generation,
    c.flowId,
    c.commandId,
    c.provider,
    c.protocol,
    c.configurationGeneration,
    c.issuer,
    c.responseIssuerMode,
    c.callbackId,
    c.redirectUri,
    c.returnTarget,
    c.stateDigest,
    c.requestBindingVerifier,
    c.requestBindingExpiresAtMillis,
    c.issuedAtMillis,
    c.expiresAtMillis,
    c.claimLifetimeMillis,
  ]),
);

const encoder = new TextEncoder();

const aad = (context: OAuthSignInTransactionContext, keyId: string) => {
  const v = snapshotOAuthSync(OAuthSignInTransactionContext, context);

  const encoded = Schema.encodeSync(aadCodec)([
    "effect-auth/oauth-sign-in-aead/v1",
    "oauth-xchacha20poly1305-v1",
    keyId,
    v.namespace,
    v.moduleId,
    v.generation,
    v.flowId,
    v.commandId,
    v.provider,
    v.protocol,
    v.configurationGeneration,
    v.issuer,
    v.responseIssuerMode,
    v.callbackId,
    v.redirectUri,
    v.returnTarget,
    v.stateDigest,
    v.requestBindingVerifier,
    v.requestBindingExpiresAtMillis,
    v.issuedAtMillis,
    v.expiresAtMillis,
    v.claimLifetimeMillis,
  ]);

  if (encoded.length > 16384) throw OAuthUnavailable.make({});
  const bytes = encoder.encode(encoded);

  if (bytes.length > 16384) {
    bytes.fill(0);
    throw OAuthUnavailable.make({});
  }

  return bytes;
};

/** Dedicated transaction encryption. Retain retired keys through every pending
 * and claimed flow horizon and deployment convergence; binder signing keys have
 * an independent retention obligation. Never reuse session or connected-token keys.
 * Redacted prevents formatting, not memory disclosure or JavaScript zeroization.
 */
export class OAuthTransactionProtector extends Context.Service<
  OAuthTransactionProtector,
  {
    readonly seal: (input: {
      readonly context: OAuthSignInTransactionContext;
      readonly secrets: OAuthTransactionSecrets;
    }) => Effect.Effect<OAuthSealedTransaction, OAuthUnavailable>;
    readonly open: (input: {
      readonly context: OAuthSignInTransactionContext;
      readonly sealed: OAuthSealedTransaction;
    }) => Effect.Effect<OAuthTransactionSecrets, OAuthUnavailable>;
  }
>()("effect-auth/OAuthTransactionProtector") {
  static readonly xchacha20poly1305 = (keyring: OAuthTransactionKeyring) =>
    Layer.effect(this, transactionEncryption(OAuthSignInTransactionContext, aad, keyring));
}
