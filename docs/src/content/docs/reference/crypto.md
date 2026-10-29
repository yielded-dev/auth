---
title: Cryptography
description: Supply Effect crypto services and bounded password-derivation backends.
---

Auth and JOSE use `effect/crypto` for secure randomness, digests, message
authentication, authenticated encryption, signatures, and key formats. Applications
own keys, nonce uniqueness, accepted algorithms, and credential policy.
Password hashing uses Effect Kdf. Auth supplies portable Argon2id and a separate
scrypt adapter, with password cost limits and shared admission.

## Compose a backend

Use the Effect platform Layer for your runtime:

```ts
import { NodeCrypto } from "@effect/platform-node";
import { Effect } from "effect";
import { Aead, SecureRandom } from "effect/crypto";

// Read a cryptographically random application key from secret configuration.
declare const keyBytes: Uint8Array;

const protect = Effect.gen(function* () {
  const random = yield* SecureRandom.SecureRandom;
  const aead = yield* Aead.Aead;
  const key = yield* Aead.key(Aead.aes256Gcm, keyBytes);
  const nonce = yield* random.randomBytes(12);
  const ciphertext = yield* aead.encrypt(
    key,
    new TextEncoder().encode("private data"),
    { nonce, aad: new TextEncoder().encode("application/purpose/v1") },
  );
  return { nonce, ciphertext };
}).pipe(Effect.provide(NodeCrypto.layer));
```

Never reuse a nonce with the same key.
Use `BunCrypto` from `@effect/platform-bun` on Bun. For WebCrypto hosts,
`@yielded/auth/WebCrypto` exports `layerWebCrypto`, supplying `SecureRandom`,
`Digest`, `Mac`, `Aead`, and `Signature`. Its `layerCryptoWeb` supplies only
`SecureRandom` and `Digest`.

Effect keys are opaque snapshots. `Mac.key` and `Aead.key` import raw bytes;
`KeyFormat` imports and exports asymmetric keys as JWK, PKCS8, or SPKI.
Keep private material out of telemetry. Effect crypto errors can carry native
causes: translate them at your application's public boundary.

## Use with Auth

Choose the services your application needs:

| Auth concern                       | Effect services                                               |
| ---------------------------------- | ------------------------------------------------------------- |
| Stateful sessions and token proofs | `SecureRandom`, `Digest`                                      |
| Signed sessions and numeric proofs | `SecureRandom`, `Digest`, `Mac`                               |
| TOTP                               | `SecureRandom`, `Digest`, `Mac`, `Aead`                       |
| OAuth protection                   | `SecureRandom`, `Aead`                                        |
| OIDC verification                  | `Signature`, plus the provider's HTTP and digest requirements |

Auth owns keyring validation, key IDs, token serialization, and authenticated
context. Its OAuth protectors use XChaCha20-Poly1305; TOTP uses AES-256-GCM.
Effect's WebCrypto AEAD Layer supplies both. Existing application configuration
continues to use redacted key bytes or base64url keyring material.

For Cloudflare Workers, provide `WorkerdPasswordlessServices.layer` from
`@yielded/auth/WorkerdPasswordlessServices`. It includes these crypto services
and a Fetch `HttpClient`, with no Wasm or Node.js compatibility requirement.
Use `WorkerdServices.layer` from `@yielded/auth/WorkerdServices` for passwords;
that Layer also supplies password hashing, Wasm Argon2id, native scrypt, and
bounded admission. Enable `nodejs_compat` and bundle with Wrangler.

Provide the selected Layer to the application once. Storage, account policy,
keys, delivery, and protocol adapters remain application-owned. Direct callers of
`Sessions.makeSessionSigningCodec` and numeric `Proofs.makeProofCrypto` must keep
the construction Scope open while using their operations. Auth Layers own that
scope when constructing them.

For manual password composition on Node:

```ts
import { NodeCrypto } from "@effect/platform-node";
import { Password } from "@yielded/auth";
import * as PasswordScrypt from "@yielded/auth/PasswordScrypt";
import { Layer } from "effect";

export const CryptoLive = Layer.mergeAll(
  NodeCrypto.layer,
  PasswordScrypt.layer,
  Password.KdfAdmission.layer(),
);

export const PasswordLive = Password.PasswordHashing.layer().pipe(
  Layer.provide(CryptoLive),
);
```

Use `BunCrypto.layer` on Bun. `Password.layerKdf` supplies portable Argon2id and
Effect WebCrypto KDFs when native Argon2id is unavailable. It can be combined with
`WebCrypto.layerWebCrypto` and `Password.KdfAdmission.layer()`.
Scrypt is optional: without `PasswordScrypt.layer`, attempts to derive or verify
scrypt fail with `PasswordHashingUnavailable`. Other password formats still work.

## Password resource limits

`PasswordHashingConfig` owns password strength, verification cost ceilings, input
length, and rehash policy. Limits apply before derivation, including for stored
verifiers. Argon2id uses version 19 and memory in KiB. Scrypt uses `cost` (N),
`blockSize` (r), and `parallelism` (p); memory includes scratch buffers, and
`N*r*p/8` must fit `maximumMemoryPasses`. Legacy PBKDF2 uses SHA-256.
An unavailable algorithm fails without downgrading. Passwords are not normalized
by the hasher.

Share one `Password.KdfAdmission.layer()` across password hashers in each runtime.
Its `concurrency`, `maxQueued`, and `maxWaitMilliseconds` options default to one
running operation, sixteen queued operations, and five seconds to acquire capacity.
The permit covers preparation, derivation, and cleanup. Waiting is interruptible;
noncancelable native work retains its permit until completion. Portable Argon2id
yields between batches on the calling thread.

Retain the built Layer for the application's lifetime to share these limits.
They do not coordinate isolates or replace a distributed rate limiter.
`WorkerdServices.layerWith` accepts `passwordHashing` and `kdfAdmission` options.
Calling Effect Kdf directly bypasses Auth's password policy and admission.

Password failures expose fixed classifications without native causes. Owned
password and output buffers are cleared after work; JavaScript and native engines
cannot guarantee erasure of every copy.

See the [password guide](../guide/passwords.md) and the
[shipped notices](https://github.com/yielded-dev/auth/blob/main/packages/auth/THIRD_PARTY_NOTICES.md)
for the retained Argon2 implementation's attribution.
