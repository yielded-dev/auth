# @yielded/crypto

Effect services for authenticated encryption, HMAC, key derivation and signatures.
Effect is its only runtime package dependency; it is independent of Auth.
Applications own keys, nonces, password
policy, envelopes and protocol formats. Use Effect `Crypto` for secure randomness
and SHA digests.

```sh
bun add @yielded/crypto@beta effect
```

Import `Aead`, `Hmac`, `Kdf`, `KdfAdmission` and `Signature` from the root. Select
an implementation through a direct backend import:

- `/WebCrypto`: native operations from an explicitly supplied `SubtleCrypto`.
- `/Portable`: WebCrypto plus owned Argon2id and XChaCha20-Poly1305 implementations.
- `/platform-node`, `/platform-bun`: shared Node-compatible WebCrypto and native
  Argon2id, plus the owned XChaCha20-Poly1305 implementation.

All backend Layers require one shared `KdfAdmission` Layer. Waiting is bounded;
once admitted, derivation retains its permit until actual work and cleanup finish,
including interruption. Portable Argon2id yields through Effect between batches
and clears its work buffers before returning, but still runs on the calling
thread. JavaScript cannot guarantee zeroization or constant-time execution.

Secret inputs, derived bytes and decrypted plaintext use `Redacted`. Backend
errors contain classifications without native causes or secret payloads. Keep
each AEAD nonce unique for its key. Signature operations use PKCS8/SPKI DER keys;
raw key components can be encoded through the native key parser.
[JOSE](../jose/README.md) and password-hash serialization belong to other layers.

See the [usage and supported profiles](../../docs/src/content/docs/reference/crypto.md)
and [third-party notices](THIRD_PARTY_NOTICES.md). The notices ship in this package.
