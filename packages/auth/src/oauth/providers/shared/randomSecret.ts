import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Redacted from "effect/Redacted";

import { OAuthUnavailable } from "../../signInErrors";

/** Mint a fresh 256-bit base64url-encoded secret for OAuth `state` or `nonce`. */
export const randomSecret: Effect.Effect<
  Redacted.Redacted<string>,
  OAuthUnavailable,
  SecureRandom.SecureRandom
> = SecureRandom.SecureRandom.use((random) =>
  Effect.flatMap(random.randomBytes(32), (bytes) =>
    bytes.length === 32
      ? Effect.succeed(Redacted.make(Base64Url.encode(bytes)))
      : Effect.fail(OAuthUnavailable.make({})),
  ),
);
