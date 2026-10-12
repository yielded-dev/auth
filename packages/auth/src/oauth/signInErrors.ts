import { Schema } from "effect";

export class OAuthRejected extends Schema.TaggedError<OAuthRejected>()("OAuthRejected", {}) {}

export class OAuthUnavailable extends Schema.TaggedError<OAuthUnavailable>()(
  "OAuthUnavailable",
  {},
) {}

export class OAuthMethodUnsupported extends Schema.TaggedError<OAuthMethodUnsupported>()(
  "OAuthMethodUnsupported",
  {},
) {}

export class OAuthProtocolRejected extends Schema.TaggedError<OAuthProtocolRejected>()(
  "OAuthProtocolRejected",
  {},
) {}

export class OAuthConfigurationError extends Schema.TaggedError<OAuthConfigurationError>()(
  "OAuthConfigurationError",
  { reason: Schema.Literals(["module", "policy", "keyring", "return-target", "crypto"]) },
) {
  override get message() {
    return this.reason === "crypto"
      ? "OAuth requires Aead support for XChaCha20-Poly1305. On Workers, use @yielded/crypto/Portable instead of @yielded/crypto/WebCrypto."
      : `Invalid OAuth configuration: ${this.reason}`;
  }
}
