import { OAuthServer } from "@yielded/auth";
import { Jwk } from "@yielded/jose";
import { Config, Context, Crypto, Effect, FileSystem, Layer, Path, Redacted, Schema } from "effect";
import { Base64Url } from "effect/encoding";

export const IdentityKeyMaterial = Schema.fromJsonString(
  Schema.Struct({
    consent: Schema.RedactedFromValue(Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/))),
    privateKey: Schema.RedactedFromValue(Jwk.PrivateJwk),
    publicKey: Jwk.PublicJwk,
  }),
);

export class YieldedKeys extends Context.Service<YieldedKeys, typeof IdentityKeyMaterial.Type>()(
  "example/YieldedKeys",
) {
  static readonly layer = Layer.effect(
    YieldedKeys,
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const entropy = yield* Crypto.Crypto;

      const directory = yield* Config.String("AUTH_DATA_DIR").pipe(
        Config.withDefault(new URL("../.data/", import.meta.url).pathname),
      );

      yield* fs.makeDirectory(directory, { recursive: true, mode: 0o700 });
      const filename = path.join(directory, "yielded-identity-keys.json");

      if (!(yield* fs.exists(filename))) {
        const pair = yield* Effect.tryPromise({
          try: () =>
            crypto.subtle.generateKey(
              {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
              },
              true,
              ["sign", "verify"],
            ),
          catch: () => OAuthServer.ConfigurationError.make({}),
        });

        const exportKey = (key: CryptoKey) =>
          Effect.tryPromise({
            try: () => crypto.subtle.exportKey("jwk", key),
            catch: () => OAuthServer.ConfigurationError.make({}),
          });

        const privateKey = yield* Schema.decodeUnknownEffect(Jwk.PrivateJwk)(
          { ...(yield* exportKey(pair.privateKey)), kid: "v1", use: "sig" },
          { reportInput: false },
        );

        const publicKey = yield* Schema.decodeUnknownEffect(Jwk.PublicJwk)({
          ...(yield* exportKey(pair.publicKey)),
          kid: "v1",
          use: "sig",
        });

        const encoded = yield* Schema.encodeEffect(IdentityKeyMaterial)({
          privateKey: Redacted.make(privateKey),
          publicKey,
          consent: Redacted.make(Base64Url.encode(yield* entropy.randomBytes(32))),
        });

        yield* fs
          .writeFileString(filename, encoded, { flag: "wx", mode: 0o600 })
          .pipe(
            Effect.catchTag("PlatformError", (error) =>
              error.reason._tag === "AlreadyExists" ? Effect.void : Effect.fail(error),
            ),
          );
      }

      return yield* Schema.decodeEffect(IdentityKeyMaterial)(yield* fs.readFileString(filename), {
        reportInput: false,
      }).pipe(Effect.mapError(() => OAuthServer.ConfigurationError.make({})));
    }),
  );
}
