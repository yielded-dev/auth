# @yielded/crypto

## 0.1.0-beta.29

### Minor Changes

- [#160](https://github.com/yielded-dev/auth/pull/160) [`536a76b`](https://github.com/yielded-dev/auth/commit/536a76b6cd7d653b456adfcf0f81d275cda77660) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Reduce portable Argon2id and HMAC scheduling overhead and XChaCha buffer allocation. Reuse AES-GCM and signature keys through scoped imports.

  BEHAVIOR CHANGE: Custom `Aead` services must implement `importKey`; custom `Signature` services must implement `importPrivateKey` and `importPublicKey` with scoped key ownership.

## 0.1.0-beta.28

No changes in this release.

## 0.1.0-beta.27

No changes in this release.

## 0.1.0-beta.26

No changes in this release.

## 0.1.0-beta.25

No changes in this release.

## 0.1.0-beta.24

No changes in this release.

## 0.1.0-beta.23

No changes in this release.

## 0.1.0-beta.22

No changes in this release.

## 0.1.0-beta.21

No changes in this release.

## 0.1.0-beta.20

## 0.1.0-beta.19

### Minor Changes

- [#107](https://github.com/yielded-dev/auth/pull/107) [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add reusable Effect crypto, Schema-typed JOSE, and OAuth/OIDC packages, and adopt them throughout Auth without changing stored credential formats. Remove unnecessary signing-service requirements from GitHub and use scoped HMAC keys for sessions and numeric proofs.

  BEHAVIOR CHANGE: Replace the former crypto/OpenID adapter imports with Auth's direct service Layers and `OpenIdConnect`/`GitHub` modules, supplying crypto and HTTP services explicitly. Implement scoped `Hmac.importKey` in custom backends, replace Auth `SubtleCrypto` overrides with `Hmac` Layers, and keep direct session/numeric-proof crypto constructors in an open Scope. Set managed storage's `prefix`, yield `Adapter.makeStorageMappings(storage)` with Effect Crypto supplied, and wrap application-owned Durable Object Drizzle databases with `SqliteDo.makeDatabase` for asynchronous transactions.

### Patch Changes

- [#107](https://github.com/yielded-dev/auth/pull/107) [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Cancel and join OAuth identity decoding when its provider scope closes. Preserve same-fiber KDF admission through scoped cleanup.
