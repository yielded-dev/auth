# @yielded/auth-platform-workerd

Cloudflare Workers runtime services for Yielded Auth. Owns the WASM Argon2id
implementation; password policy and admission remain in Auth.

```sh
bun add @yielded/auth-platform-workerd@beta @yielded/auth@beta effect
```

Provide `layer` from the package root for crypto, HTTP, and password hashing.
Use `layerWith({ passwordHashing, kdfAdmission })` to configure costs and capacity.
The root requires `nodejs_compat`; Wrangler bundles the included WASM asset.
Applications without password hashing can compose `effect/crypto` WebCrypto
Layers and `FetchHttpClient.layer` directly, without this package.

Retain the built Layer across requests to share password admission limits.
Applications supply storage, account policy, keys, delivery, and protocol adapters.
