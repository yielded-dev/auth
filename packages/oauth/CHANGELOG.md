# @yielded/oauth

## 0.1.0-beta.24

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.24

## 0.1.0-beta.23

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.23

## 0.1.0-beta.22

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.22

## 0.1.0-beta.21

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.21

## 0.1.0-beta.20

### Patch Changes

- [#123](https://github.com/yielded-dev/auth/pull/123) [`0c61f7a`](https://github.com/yielded-dev/auth/commit/0c61f7a766766929d642cc8e17b6091c89ea62e9) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Support OAuth requests on Cloudflare Workers while continuing to reject provider redirects.

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.20

## 0.1.0-beta.19

### Minor Changes

- [#107](https://github.com/yielded-dev/auth/pull/107) [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add reusable Effect crypto, Schema-typed JOSE, and OAuth/OIDC packages, and adopt them throughout Auth without changing stored credential formats. Remove unnecessary signing-service requirements from GitHub and use scoped HMAC keys for sessions and numeric proofs.

  BEHAVIOR CHANGE: Replace the former crypto/OpenID adapter imports with Auth's direct service Layers and `OpenIdConnect`/`GitHub` modules, supplying crypto and HTTP services explicitly. Implement scoped `Hmac.importKey` in custom backends, replace Auth `SubtleCrypto` overrides with `Hmac` Layers, and keep direct session/numeric-proof crypto constructors in an open Scope. Set managed storage's `prefix`, yield `Adapter.makeStorageMappings(storage)` with Effect Crypto supplied, and wrap application-owned Durable Object Drizzle databases with `SqliteDo.makeDatabase` for asynchronous transactions.

### Patch Changes

- [#107](https://github.com/yielded-dev/auth/pull/107) [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Require application-supplied crypto Layers throughout Auth and acquire storage-mapping dependencies through Effect requirements. Remove the unused Hmac requirement from JWKS and OIDC verification.

  BEHAVIOR CHANGE: Replace `Persistence.cryptoLayer` with your selected backend and provide it to the Auth Layer. Yield `Adapter.makeStorageMappings(storage)` inside an Effect with `Crypto` supplied.

- Updated dependencies [[`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a), [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a)]:
  - @yielded/jose@0.1.0-beta.19
