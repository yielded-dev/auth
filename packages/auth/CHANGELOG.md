# @yielded/auth

## 0.1.0-beta.6

### Minor Changes

- [#21](https://github.com/yielded-dev/auth/pull/21) [`72a5ab0`](https://github.com/yielded-dev/auth/commit/72a5ab0f0c9d246eaf598122a6a3bbd38bf2b199) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Mount auth with `AuthHttp.layer` and configure OAuth providers with generated callback routes, signed-cookie flow recovery, and callback customization.

  BEHAVIOR CHANGE: Use `GitHub.provider` in the HTTP provider map; use `gitHubOAuthAppProvider` for explicit provider entries in `OpenIdClient.layer`.

- [#22](https://github.com/yielded-dev/auth/pull/22) [`26cee88`](https://github.com/yielded-dev/auth/commit/26cee88102f72cd1483383720a5478234972326c) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Start OAuth sign-in with only `provider` and `returnTarget`; generate attempt IDs on the server and select the configured default callback.

  BEHAVIOR CHANGE: Remove `flowId` and `commandId` from named sign-in calls. Custom `OAuthProtocol` implementations must resolve an omitted `callbackId` to the provider-named callback or the only configured callback, and reject ambiguous selection.

### Patch Changes

- [#19](https://github.com/yielded-dev/auth/pull/19) [`11140f3`](https://github.com/yielded-dev/auth/commit/11140f30362c523516cef727ff81cabcb613ccb3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Configure GitHub sign-in with `GitHub.layer({ clientId, clientSecret, redirectUri })` and compose hosts with `GitHub.provider` and `OpenIdClient.layer`. Apply the same callback, generation, issuance, and timeout defaults to connected accounts through `GitHub.layerConnected` and `OpenIdClientConnected.layer`, while retaining explicit rotation and provider security settings.

## 0.1.0-beta.5

### Patch Changes

- [#17](https://github.com/yielded-dev/auth/pull/17) [`098ad4a`](https://github.com/yielded-dev/auth/commit/098ad4a416e619a4ee9d44cbee36b5a924d6b595) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Expose complete documented GitHub user profiles and standard OIDC user claims with typed schemas and normalized display fields. Pass the authenticated profile to registration authority and sign-in claims resolvers while keeping local identity and public session claims application-owned.

## 0.1.0-beta.4

### Patch Changes

- [#15](https://github.com/yielded-dev/auth/pull/15) [`85edaa4`](https://github.com/yielded-dev/auth/commit/85edaa44b4186d2aaf37c7007441ee9803c990cf) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Validate GitHub OAuth callbacks against the required `https://github.com/login/oauth` issuer. BEHAVIOR CHANGE: restart pending flows and follow the OAuth guide to re-establish GitHub bindings or grants created with the old issuer; other providers and application data are unaffected.

## 0.1.0-beta.3

### Patch Changes

- [#12](https://github.com/yielded-dev/auth/pull/12) [`0f7bf1a`](https://github.com/yielded-dev/auth/commit/0f7bf1abe572a6b271b74c92173ecde906618287) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Configure GitHub OAuth App sign-in alongside generic OAuth/OIDC providers in one protocol layer using `gitHubOAuthAppProvider`, preserving GitHub response handling and captured provider generations.

## 0.1.0-beta.2

### Patch Changes

- [#9](https://github.com/yielded-dev/auth/pull/9) [`4e241f0`](https://github.com/yielded-dev/auth/commit/4e241f0dd31a4f857e5d3a17043c17139d540e8f) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Point package source and issue links to the `yielded-dev/auth` repository. Link the package homepage to `yielded.dev/auth`.

## 0.1.0-beta.1

### Minor Changes

- [#5](https://github.com/yielded-dev/auth/pull/5) [`32be91d`](https://github.com/yielded-dev/auth/commit/32be91d23f8b17e8eff479a4ed2456b1d8fdc373) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Define shared auth contracts for request-aware local services, named HTTP clients, and automatically synchronized Effect Atom state. Compose auth routes with existing HttpApi groups and use importable Effect Atom queries and mutations with scoped session hydration and shared invalidation.

  BEHAVIOR CHANGE: Create service definitions with `Auth.make(contractOrId, options)` and `Client.make(contract, options)`; construct instances with their `.make` Effects. Include `credentials` in manually provided `AuthRequest` values. Mount shared actions with `http.routes()`; session lookup and required-session lookup use GET; sign-out and renewal use POST at their named `/auth` paths. Apply `http.protect` to custom credential-producing HTTP workflows. Set `basePath` in `AuthContract.make` to change their shared prefix.

- [`f8916bd`](https://github.com/yielded-dev/auth/commit/f8916bdb4e13264f332ddb036f3cd9d8ba0bb95c) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Publish Yielded Auth as `@yielded/auth` with the same root namespaces and direct module exports. Use `@yielded/auth` and `@yielded/auth/<Module>` in application imports.

### Patch Changes

- [#2](https://github.com/yielded-dev/auth/pull/2) [`d85cc73`](https://github.com/yielded-dev/auth/commit/d85cc73b18c5c4939cf7466a76277df203192551) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Preserve module boundaries and native root namespaces so consumers can tree-shake unused implementations. Expose SessionContract from the package root alongside the other shared contracts.
