import { Context, Crypto, Effect, Encoding, Layer, Redacted, Result, Schema } from "effect";

import { AuthTokenError, InvalidSession } from "./Errors";
import {
  KeyedDigest,
  type KeyId,
  OtpDigest,
  SessionClaims,
  SessionToken,
  TokenDigest,
} from "./Schema";
import { SubtleCrypto } from "./WebCrypto";

/**
 * HMAC keyring: one active signing key plus verification keys retained until
 * their sessions expire. Every secret must hold at least 256 random bits.
 */
export class AuthKeyring extends Context.Service<
  AuthKeyring,
  {
    readonly activeKeyId: KeyId;
    readonly keys: ReadonlyArray<{
      readonly keyId: KeyId;
      readonly secret: Redacted.Redacted<string>;
    }>;
  }
>()("effect-auth/AuthKeyring") {}

export interface AuthTokenCodecService {
  readonly activeKeyId: KeyId;
  /** Active key first, then verification-only keys. */
  readonly keyIds: ReadonlyArray<KeyId>;
  readonly encodeSession: (claims: SessionClaims) => Effect.Effect<SessionToken, AuthTokenError>;
  /** Checks format, key id, and signature. Time and policy checks belong to `AuthSession`. */
  readonly decodeSession: (
    token: Redacted.Redacted<string>,
  ) => Effect.Effect<SessionClaims, InvalidSession | AuthTokenError>;
  /** Unkeyed digest for high-entropy tokens; stable across key rotation. */
  readonly digestToken: (
    token: Redacted.Redacted<string>,
    scope: string,
  ) => Effect.Effect<TokenDigest, AuthTokenError>;
  /** Keyed digest for low-entropy secrets, scoped so digests cannot be transplanted. */
  readonly digestSecret: (
    value: Redacted.Redacted<string>,
    scope: string,
    keyId?: KeyId,
  ) => Effect.Effect<KeyedDigest, AuthTokenError>;
}

const envelopeVersion = "eav1";
const textEncoder = new TextEncoder();

// One JSON-string codec owns the token payload text, both directions. Plain
// `fromJsonString` (no `toCodecJson`): the opaque `ext` claims slot keeps
// native `JSON.stringify` semantics.
const SessionClaimsJson = Schema.fromJsonString(SessionClaims);
const encodeClaimsJson = Schema.encodeEffect(SessionClaimsJson);
const decodeClaimsJson = Schema.decodeEffect(SessionClaimsJson);
const tokenDigestFromString = Schema.decodeEffect(TokenDigest);
const otpDigestFromString = Schema.decodeEffect(OtpDigest);
const sessionTokenFromString = Schema.decodeEffect(SessionToken);

/**
 * Default HMAC-SHA-256 codec on WebCrypto. Signing keys never leave the
 * runtime's key store; secure random bytes come from `Crypto.Crypto`.
 */
const makeWebCryptoCodec: Effect.Effect<
  AuthTokenCodecService,
  AuthTokenError,
  AuthKeyring | Crypto.Crypto | SubtleCrypto
> = Effect.gen(function* () {
  const keyring = yield* AuthKeyring;
  const crypto = yield* Crypto.Crypto;
  const subtle = yield* SubtleCrypto;

  if (!keyring.keys.some((key) => key.keyId === keyring.activeKeyId)) {
    return yield* AuthTokenError.make({
      message: "Keyring does not contain the active signing key",
    });
  }

  const importKey = (secret: Redacted.Redacted<string>) =>
    Effect.tryPromise({
      try: () =>
        subtle.importKey(
          "raw",
          textEncoder.encode(Redacted.value(secret)),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign", "verify"],
        ),
      catch: () => AuthTokenError.make({ message: "Failed to import HMAC key" }),
    });

  const keys = new Map<KeyId, CryptoKey>();

  for (const entry of keyring.keys) {
    keys.set(entry.keyId, yield* importKey(entry.secret));
  }

  const hmac = (keyId: KeyId, data: Uint8Array) =>
    Effect.gen(function* () {
      const key = keys.get(keyId);

      if (key === undefined) {
        return yield* AuthTokenError.make({ message: "Unknown key id" });
      }

      const signature = yield* Effect.tryPromise({
        try: () => subtle.sign("HMAC", key, data as BufferSource),
        catch: () => AuthTokenError.make({ message: "HMAC signing failed" }),
      });

      return new Uint8Array(signature);
    });

  const hmacVerify = (keyId: KeyId, data: Uint8Array, signature: Uint8Array) =>
    Effect.gen(function* () {
      const key = keys.get(keyId);

      if (key === undefined) {
        return false;
      }

      return yield* Effect.tryPromise({
        try: () => subtle.verify("HMAC", key, signature as BufferSource, data as BufferSource),
        catch: () => AuthTokenError.make({ message: "HMAC verification failed" }),
      });
    });

  return {
    activeKeyId: keyring.activeKeyId,
    keyIds: [
      keyring.activeKeyId,
      ...keyring.keys.map((key) => key.keyId).filter((id) => id !== keyring.activeKeyId),
    ],

    encodeSession: Effect.fn("AuthTokenCodec.encodeSession")(function* (claims) {
      const encoded = yield* encodeClaimsJson(claims).pipe(
        Effect.mapError(() => AuthTokenError.make({ message: "Session claims failed to encode" })),
      );

      const payload = Encoding.encodeBase64Url(encoded);
      const signingInput = `${envelopeVersion}.${payload}`;
      const signature = yield* hmac(claims.kid, textEncoder.encode(signingInput));
      const token = `${signingInput}.${Encoding.encodeBase64Url(signature)}`;

      return yield* sessionTokenFromString(token).pipe(
        Effect.mapError(() => AuthTokenError.make({ message: "Session token failed to encode" })),
      );
    }),

    decodeSession: Effect.fn("AuthTokenCodec.decodeSession")(function* (token) {
      const [version, payloadPart, signaturePart, ...rest] = Redacted.value(token).split(".");

      if (
        version !== envelopeVersion ||
        payloadPart === undefined ||
        signaturePart === undefined ||
        rest.length > 0
      ) {
        return yield* InvalidSession.make();
      }
      const payloadJson = Result.getOrUndefined(Encoding.decodeBase64UrlString(payloadPart));
      const signature = Result.getOrUndefined(Encoding.decodeBase64Url(signaturePart));

      if (payloadJson === undefined || signature === undefined) {
        return yield* InvalidSession.make();
      }

      const claims = yield* decodeClaimsJson(payloadJson).pipe(
        Effect.mapError(() => InvalidSession.make()),
      );

      const signingInput = `${envelopeVersion}.${payloadPart}`;
      const valid = yield* hmacVerify(claims.kid, textEncoder.encode(signingInput), signature);

      if (!valid) {
        return yield* InvalidSession.make();
      }

      return claims;
    }),

    digestToken: Effect.fn("AuthTokenCodec.digestToken")(function* (token, scope) {
      const data = textEncoder.encode(`${scope}\n${Redacted.value(token)}`);

      const digest = yield* crypto
        .digest("SHA-256", data)
        .pipe(Effect.mapError(() => AuthTokenError.make({ message: "Token digest failed" })));

      return yield* tokenDigestFromString(Encoding.encodeBase64Url(digest)).pipe(
        Effect.mapError(() => AuthTokenError.make({ message: "Token digest failed to encode" })),
      );
    }),

    digestSecret: Effect.fn("AuthTokenCodec.digestSecret")(function* (value, scope, keyId) {
      const resolvedKeyId = keyId ?? keyring.activeKeyId;
      const data = textEncoder.encode(`${scope}\n${Redacted.value(value)}`);
      const digest = yield* hmac(resolvedKeyId, data);

      const otpDigest = yield* otpDigestFromString(Encoding.encodeBase64Url(digest)).pipe(
        Effect.mapError(() => AuthTokenError.make({ message: "Secret digest failed to encode" })),
      );

      return KeyedDigest.make({ keyId: resolvedKeyId, digest: otpDigest });
    }),
  };
});

export class AuthTokenCodec extends Context.Service<AuthTokenCodec, AuthTokenCodecService>()(
  "effect-auth/AuthTokenCodec",
) {
  /**
   * Default HMAC implementation backed by WebCrypto. The consumer may replace
   * it with its own codec service.
   */
  static readonly layerWebCrypto: Layer.Layer<
    AuthTokenCodec,
    AuthTokenError,
    AuthKeyring | Crypto.Crypto
  > = Layer.effect(AuthTokenCodec)(makeWebCryptoCodec).pipe(Layer.provide(SubtleCrypto.layerWeb));

  static readonly layer = AuthTokenCodec.layerWebCrypto;
}
