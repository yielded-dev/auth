import { Layer, Redacted, Schema } from "effect";

import { AuthKeyring } from "../AuthTokenCodec";
import { KeyId } from "../Schema";

export const testKeyId = Schema.decodeSync(KeyId)("test-key-1");

/** Static single-key keyring for tests; the secret is intentionally well known. */
export const layerKeyringTest = Layer.succeed(AuthKeyring)({
  activeKeyId: testKeyId,
  keys: [
    {
      keyId: testKeyId,
      secret: Redacted.make("effect-auth-test-secret-0123456789abcdef0123456789abcdef"),
    },
  ],
});
