import { Schema } from "effect";

import { OAuthUnavailable } from "../signInErrors";
import {
  OAuthEncryptionKeyId,
  OAuthSealedTransaction,
  OAuthTransactionSecrets,
  OAuthSignInTransactionContext,
} from "../signInModels";
import { snapshotOAuthSync } from "../signInSnapshot";
import { type OAuthTransactionKeyring } from "../transactionKeyring";
import { transactionEncryption } from "./transaction-encryption";
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

export const make = (keyring: OAuthTransactionKeyring) =>
  transactionEncryption(OAuthSignInTransactionContext, aad, keyring, OAuthTransactionSecrets);
