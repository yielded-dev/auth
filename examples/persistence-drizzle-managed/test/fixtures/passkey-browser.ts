import { isoCBOR } from "@simplewebauthn/server/helpers";
import { PasskeyBrowser, PasskeyBrowserNotCompleted } from "@yielded/auth/PasskeyBrowser";
import { Effect, Encoding, Layer, Redacted } from "effect";

// A software authenticator; requests still pass through the real WebAuthn server verifier.
export const makePasskeyBrowser = Effect.fn("test.makePasskeyBrowser")(function* (origin: string) {
  const keys = yield* Effect.promise(() =>
    crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]),
  );

  const jwk = yield* Effect.promise(() => crypto.subtle.exportKey("jwk", keys.publicKey));
  const encode = Encoding.encodeBase64Url;

  const decode = (value: string) => {
    const result = Encoding.decodeBase64Url(value);

    if (result._tag === "Failure") throw new Error("Invalid fixture base64url");

    return result.success;
  };

  const concat = (...values: ReadonlyArray<Uint8Array>) =>
    new Uint8Array(values.flatMap((value) => Array.from(value)));

  const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

  const hash = (value: Uint8Array) =>
    Effect.promise(() => crypto.subtle.digest("SHA-256", new Uint8Array(value))).pipe(
      Effect.map((buffer) => new Uint8Array(buffer)),
    );

  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const id = encode(credentialId);
  const rpHash = yield* hash(new TextEncoder().encode(new URL(origin).hostname));

  if (jwk.x === undefined || jwk.y === undefined) throw new Error("Missing fixture coordinates");

  const publicKey = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, decode(jwk.x)],
      [-3, decode(jwk.y)],
    ]),
  );

  let handle = "";
  let counter = 0;
  const state = { cancel: false, registrations: 0 };

  const browser = PasskeyBrowser.of({
    capabilities: Effect.succeed({
      secureContext: true,
      webAuthn: true,
      conditionalGet: "unsupported",
      userVerifyingPlatformAuthenticator: "supported",
      hybridTransport: "unknown",
      passkeyPlatformAuthenticator: "supported",
    }),
    register: Effect.fn("test.registerPasskey")(function* (started) {
      state.registrations++;
      if (state.cancel) return yield* PasskeyBrowserNotCompleted.make({});
      handle = started.options.user.id;

      const authData = concat(
        rpHash,
        new Uint8Array([0x45, 0, 0, 0, 0]),
        new Uint8Array(16),
        new Uint8Array([0, credentialId.length]),
        credentialId,
        publicKey,
      );

      const attestation = isoCBOR.encode(
        new Map<string, string | Uint8Array | Map<string, never>>([
          ["fmt", "none"],
          ["attStmt", new Map<string, never>()],
          ["authData", authData],
        ]),
      );

      return {
        flowId: started.flowId,
        response: Redacted.make(
          JSON.stringify({
            id,
            rawId: id,
            type: "public-key",
            response: {
              clientDataJSON: encode(
                json({
                  type: "webauthn.create",
                  challenge: started.options.challenge,
                  origin,
                  crossOrigin: false,
                }),
              ),
              attestationObject: encode(attestation),
            },
            clientExtensionResults: {},
            authenticatorAttachment: "platform",
          }),
        ),
      };
    }),
    authenticate: Effect.fn("test.authenticatePasskey")(function* ({ started }) {
      const clientData = json({
        type: "webauthn.get",
        challenge: started.options.challenge,
        origin,
        crossOrigin: false,
      });

      const count = new Uint8Array(4);

      new DataView(count.buffer).setUint32(0, ++counter);
      const authData = concat(rpHash, new Uint8Array([0x05]), count);
      const signed = concat(authData, yield* hash(clientData));

      const raw = new Uint8Array(
        yield* Effect.promise(() =>
          crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, signed),
        ),
      );

      const integer = (part: Uint8Array) => {
        let start = 0;

        while (start < part.length - 1 && part[start] === 0) start++;

        const value =
          part[start] & 0x80 ? concat(new Uint8Array([0]), part.slice(start)) : part.slice(start);

        return concat(new Uint8Array([2, value.length]), value);
      };

      const parts = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
      const signature = concat(new Uint8Array([0x30, parts.length]), parts);

      return {
        flowId: started.flowId,
        response: Redacted.make(
          JSON.stringify({
            id,
            rawId: id,
            type: "public-key",
            response: {
              clientDataJSON: encode(clientData),
              authenticatorData: encode(authData),
              signature: encode(signature),
              userHandle: handle,
            },
            clientExtensionResults: {},
            authenticatorAttachment: "platform",
          }),
        ),
      };
    }),
  });

  return { state, layer: Layer.succeed(PasskeyBrowser, browser) };
});
