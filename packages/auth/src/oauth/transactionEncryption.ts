// oxlint-disable-next-line import/extensions -- Noble exposes only its explicit .js subpath.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Crypto, Effect, Encoding, Redacted, Result, Schema } from "effect";

import { OAuthConfigurationError, OAuthUnavailable } from "./signInErrors";
import {
  OAuthEncryptionKeyId,
  OAuthSealedTransaction,
  OAuthTransactionSecrets,
} from "./signInModels";
import { snapshotOAuthSync } from "./signInSnapshot";

export interface OAuthTransactionKeyring {
  readonly activeKeyId: string;
  readonly keys: ReadonlyArray<{
    readonly id: string;
    readonly material: Redacted.Redacted<string>;
  }>;
}

const keyringSchema = Schema.Struct({
  activeKeyId: OAuthEncryptionKeyId,
  keys: Schema.Array(
    Schema.Struct({
      id: OAuthEncryptionKeyId,
      material: Schema.Redacted(Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/))),
    }),
  ).check(Schema.isMinLength(1), Schema.isMaxLength(8)),
});

const encoder = new TextEncoder();
const secretCodec = Schema.fromJsonString(OAuthTransactionSecrets);

const decodeBase64 = (value: string, maximum: number, exact?: number) => {
  if (
    value.length > Math.ceil((maximum * 4) / 3) ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw OAuthUnavailable.make({});
  }
  const bytes = Result.getOrUndefined(Encoding.decodeBase64Url(value));

  if (
    !bytes ||
    bytes.length > maximum ||
    (exact !== undefined && bytes.length !== exact) ||
    Encoding.encodeBase64Url(bytes) !== value
  ) {
    bytes?.fill(0);
    throw OAuthUnavailable.make({});
  }

  return bytes;
};

const validateSecrets = (
  context: { readonly protocol: "oidc" | "oauth" },
  secrets: OAuthTransactionSecrets,
) => {
  const value = snapshotOAuthSync(OAuthTransactionSecrets, secrets);

  if ((context.protocol === "oidc") !== (value.oidcNonce !== undefined))
    throw OAuthUnavailable.make({});
  for (const raw of [value.state, value.oidcNonce]) {
    if (raw !== undefined) decodeBase64(Redacted.value(raw), 32, 32).fill(0);
  }

  return value;
};

/** Private primitive: public protectors each own a fixed typed AAD domain. */
export const transactionEncryption = <C extends { readonly protocol: "oidc" | "oauth" }>(
  contextSchema: Schema.Codec<C, unknown, never, never>,
  aad: (context: C, keyId: string) => Uint8Array,
  keyring: OAuthTransactionKeyring,
) => {
  let captured: typeof keyringSchema.Type | undefined;

  try {
    captured = snapshotOAuthSync(keyringSchema, keyring);
  } catch {
    /* validated by Layer */
  }

  return Effect.gen(function* () {
    if (captured === undefined) return yield* OAuthConfigurationError.make({ reason: "keyring" });
    const configuration = captured;
    const crypto = yield* Crypto.Crypto;
    const randomBytes = crypto.randomBytes;

    const keys = yield* Effect.try({
      try: () => {
        const map = new Map<string, Uint8Array>();

        try {
          for (const entry of configuration.keys) {
            if (map.has(entry.id)) throw OAuthUnavailable.make({});
            map.set(entry.id, decodeBase64(Redacted.value(entry.material), 32, 32));
          }
          if (!map.has(configuration.activeKeyId)) throw OAuthUnavailable.make({});

          return map;
        } catch (error) {
          for (const key of map.values()) key.fill(0);
          throw error;
        }
      },
      catch: () => OAuthConfigurationError.make({ reason: "keyring" }),
    });

    return {
      seal: Effect.fn("OAuthTransactionProtector.seal")(function* (input: {
        readonly context: C;
        readonly secrets: OAuthTransactionSecrets;
      }) {
        const retained = yield* Effect.try({
          try: () => ({
            context: snapshotOAuthSync(contextSchema, input.context),
            secrets: validateSecrets(input.context, input.secrets),
          }),
          catch: () => OAuthUnavailable.make({}),
        });

        const nonce = yield* randomBytes(24).pipe(Effect.mapError(() => OAuthUnavailable.make({})));

        return yield* Effect.try({
          try: () => {
            let plaintext: Uint8Array | undefined;
            let ciphertext: Uint8Array | undefined;
            let associated: Uint8Array | undefined;

            try {
              plaintext = encoder.encode(Schema.encodeSync(secretCodec)(retained.secrets));
              associated = aad(retained.context, configuration.activeKeyId);
              if (plaintext.length > 16384 || nonce.length !== 24) throw OAuthUnavailable.make({});
              ciphertext = xchacha20poly1305(
                keys.get(configuration.activeKeyId)!,
                nonce,
                associated,
              ).encrypt(plaintext);

              return snapshotOAuthSync(OAuthSealedTransaction, {
                format: "oauth-xchacha20poly1305-v1",
                keyId: configuration.activeKeyId,
                nonce: Encoding.encodeBase64Url(nonce),
                ciphertext: Redacted.make(Encoding.encodeBase64Url(ciphertext)),
              });
            } finally {
              plaintext?.fill(0);
              ciphertext?.fill(0);
              associated?.fill(0);
              nonce.fill(0);
            }
          },
          catch: () => OAuthUnavailable.make({}),
        });
      }),
      open: Effect.fn("OAuthTransactionProtector.open")(
        (input: { readonly context: C; readonly sealed: OAuthSealedTransaction }) =>
          Effect.try({
            try: () => {
              const context = snapshotOAuthSync(contextSchema, input.context);
              const sealed = snapshotOAuthSync(OAuthSealedTransaction, input.sealed);
              const key = keys.get(sealed.keyId);

              if (!key) throw OAuthUnavailable.make({});
              let nonce: Uint8Array | undefined;
              let ciphertext: Uint8Array | undefined;
              let associated: Uint8Array | undefined;
              let plaintext: Uint8Array | undefined;

              try {
                nonce = decodeBase64(sealed.nonce, 24, 24);
                ciphertext = decodeBase64(Redacted.value(sealed.ciphertext), 16400);
                associated = aad(context, sealed.keyId);
                plaintext = xchacha20poly1305(key, nonce, associated).decrypt(ciphertext);
                if (plaintext.length > 16384) throw OAuthUnavailable.make({});
                const json = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
                const secrets = Schema.decodeSync(secretCodec)(json);

                if (Schema.encodeSync(secretCodec)(secrets) !== json)
                  throw OAuthUnavailable.make({});

                return validateSecrets(context, secrets);
              } finally {
                nonce?.fill(0);
                ciphertext?.fill(0);
                associated?.fill(0);
                plaintext?.fill(0);
              }
            },
            catch: () => OAuthUnavailable.make({}),
          }),
      ),
    };
  });
};
