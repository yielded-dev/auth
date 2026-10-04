---
title: Reusable cryptography
description: Compose independent Effect crypto services with explicit runtime backends.
---

`@yielded/crypto` provides byte operations independently of Auth. Its services own
cryptographic execution; your application owns keys, nonce uniqueness, password
policy, trusted algorithms and envelope formats. Use Effect `Crypto` for entropy
and SHA digests. Auth's existing adapters remain the integration entrypoints for
[passwords](../guide/passwords.md), [TOTP](../guide/totp.mdx) and
[OAuth](../guide/oauth.mdx).

## Compose a backend

```sh
bun add @yielded/crypto@beta effect @effect/platform-node
```

Import services from the root and backends from their direct modules. Share one
admission Layer across backend instances so they share the same resource budget.

```ts
import { NodeCrypto as PlatformCrypto } from "@effect/platform-node";
import { Aead, KdfAdmission } from "@yielded/crypto";
import * as NodeCrypto from "@yielded/crypto/NodeCrypto";
import { Crypto, Effect, Layer, Redacted } from "effect";

const Admission = KdfAdmission.layer({ concurrency: 1, maxQueued: 16 });
const Cryptography = Layer.merge(
  PlatformCrypto.layer,
  NodeCrypto.layer().pipe(Layer.provide(Admission)),
);

// Load this application-owned 32-byte key from your secret configuration.
declare const key: Redacted.Redacted<Uint8Array>;

const protect = Effect.gen(function* () {
  const random = yield* Crypto.Crypto;
  const aead = yield* Aead.Aead;
  const nonce = yield* random.randomBytes(12);
  const ciphertext = yield* aead.encrypt({
    algorithm: "AES-256-GCM",
    key,
    nonce,
    plaintext: Redacted.make(new TextEncoder().encode("private data")),
    additionalData: new TextEncoder().encode("application/purpose/v1"),
  });

  return { nonce, ciphertext };
}).pipe(Effect.provide(Cryptography));
```

For a supplied WebCrypto capability, use
`WebCrypto.layer(globalThis.crypto.subtle)` from `@yielded/crypto/WebCrypto`.
Choose `Portable.layer(globalThis.crypto.subtle)` from `@yielded/crypto/Portable`
when you also need portable Argon2id and XChaCha20-Poly1305. Each accepts an optional
second argument containing KDF limit overrides; `NodeCrypto.layer(limits?)`
takes those overrides as its first argument.

## Supported profiles

| Service               | Profile                                      | Bytes and key formats                                                             |
| --------------------- | -------------------------------------------- | --------------------------------------------------------------------------------- |
| `Aead.Aead`           | `AES-256-GCM`                                | 32-byte key, 12-byte nonce, 16-byte appended authentication tag                   |
| `Aead.Aead`           | `XChaCha20-Poly1305`                         | 32-byte key, 24-byte nonce, 16-byte appended authentication tag                   |
| `Hmac.Hmac`           | `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`     | Nonempty secret key; complete MAC, without truncation                             |
| `Kdf.Kdf`             | `pbkdf2`, `hkdf`                             | SHA-256; lengths are bytes                                                        |
| `Kdf.Kdf`             | `argon2id`                                   | Version 19; memory in KiB; optional secret and associated data                    |
| `Signature.Signature` | `ECDSA-P256-SHA256`                          | 64-byte IEEE P1363 signature (`r \|\| s`)                                         |
| `Signature.Signature` | `RSASSA-PKCS1-v1_5-SHA256`, `RSA-PSS-SHA256` | RSA keys of at least 2048 bits; PSS uses SHA-256, MGF1-SHA-256 and a 32-byte salt |
| `Signature.Signature` | `Ed25519`                                    | Pure Ed25519, 64-byte signature                                                   |

Signature signing takes a `Redacted` PKCS8 DER private key; verification takes an
SPKI DER public key. Keys are limited to 16 KiB of DER. This package does not parse
JWK, JWT, PHC password hashes, PEM text or Auth envelopes. SHA-1 HMAC is available
for existing protocols such as TOTP.

## Backends and resource limits

| Backend      | Native operations                             | Portable operations        | Unsupported operations                              |
| ------------ | --------------------------------------------- | -------------------------- | --------------------------------------------------- |
| `WebCrypto`  | AES-GCM, HMAC, PBKDF2, HKDF, signatures       | None                       | Argon2id, XChaCha                                   |
| `Portable`   | AES-GCM, HMAC, PBKDF2, HKDF, signatures       | Noble Argon2id and XChaCha | Host-specific native capability gaps                |
| `NodeCrypto` | Node WebCrypto operations and native Argon2id | Noble XChaCha              | Native Argon2id when the host lacks `crypto.argon2` |

Backend selection is explicit. An unavailable native algorithm fails with
`CryptoUnsupportedAlgorithm`; it does not silently select a different algorithm
or password cost. The selected vectors pass on Node 24.21 and Bun 1.4.2.
Other host WebCrypto implementations can differ; browser runtime coverage is not
claimed by the presence of a WebCrypto-shaped API.

`Kdf.defaultLimits` defines per-derivation resource ceilings. Backend construction
validates overrides before exposing services. These are work limits, not a
password-strength policy. Raising them does not widen the algorithm's numeric
domain. The HKDF profile limits `info` to 1024 bytes and output to 8160 bytes;
PBKDF2 iterations must fit a positive signed 32-bit integer. KDF inputs are bytes:
the library neither decodes nor normalizes passwords. Auth owns password
validation, PHC parsing and rehash policy.

`KdfAdmission.layer()` defaults to one running derivation, sixteen queued requests
and a five-second acquisition wait. Waiting can be interrupted. Once native work
starts, interruption waits for the work and cleanup to finish before releasing
capacity. Portable Argon2id remains on the calling thread even though it yields.

## Failure and secret boundaries

HMAC and signature verification return `false` for mismatches. Authenticated
decryption returns `CryptoAuthenticationFailed` without releasing plaintext.
Malformed keys, nonces and parameters return `CryptoInvalidInput`; backend failures
return `CryptoUnavailable`; admission overload or wait expiry returns
`CryptoKdfBusy`. These errors retain no native diagnostic cause.

Keys, passwords, decrypted plaintext and derived material use `Redacted`.
Secret-bearing input schemas reject JSON encoding. Owned secret copies are cleared
after work, without mutating caller buffers; JavaScript and native engines do not
provide a guarantee that all secret copies are erased. Scope any retained secrets
and use dedicated keys for each application purpose.

The [shipped third-party notices](https://github.com/yielded-dev/auth/blob/main/packages/crypto/THIRD_PARTY_NOTICES.md)
credit selected Noble, Wycheproof and standards sources. The initial profile does
not claim full parity with those libraries.
