import * as Context from "effect/Context";
import type * as Signature from "effect/crypto/Signature";
import type * as Effect from "effect/Effect";
import type * as Jwks from "effect/jose/Jwks";
import * as Layer from "effect/Layer";
import type * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import { reportAuthFailure, ReportedOperationDefect } from "./internal/diagnostics";
import {
  makeLocalVerifier,
  makeVerifier,
  type AccessTokenClaims,
  type AccessTokenVerifierOptions,
  type AccessTokenVerifierWithKeySetOptions,
} from "./oauth/server/access-token";
import {
  defaultConsentRenderer,
  defaultOpenIdConsent,
  type Consent as ServerConsent,
  type ConsentRendererService,
  type OpenIdConsentService,
} from "./oauth/server/consent";
import {
  makeAccessSchema,
  makeAuthenticationSchema,
  makeRecordSchema,
  Scope,
  type Access as ServerAccess,
  type Authentication as ServerAuthentication,
  type ConfigurationError,
  type InvalidToken,
  type PersistenceService,
  type Record as ServerRecord,
  type Unavailable,
} from "./oauth/server/models";
import {
  makeOAuthServer,
  makeOpenIdServer,
  type OpenIdIdentity as ServerOpenIdIdentity,
  type ServerBinding,
} from "./oauth/server/server";
import type * as OAuthScope from "./OAuthScope";
import { SubjectId } from "./Schema";

/** Verified application authentication, never values supplied by an OAuth client. */
export const Authentication = /* @__PURE__ */ makeAuthenticationSchema(SubjectId);

export type Authentication = ServerAuthentication<SubjectId>;

/** One record owns consent, code redemption and the entire refresh family.
 * Revocation is monotonic; a stale CAS must never reactivate a revoked grant.
 * No bearer credentials or provider tokens are persisted here.
 */
export const Record = /* @__PURE__ */ makeRecordSchema(SubjectId);

export type Record = ServerRecord<SubjectId>;

export const Access = /* @__PURE__ */ makeAccessSchema(Scope, SubjectId);

export type Access<Scope extends OAuthScope.OAuthScope = OAuthScope.OAuthScope> = ServerAccess<
  Scope,
  SubjectId
>;

/** Request-local authenticated authority. Absent outside protected requests;
 * callers must reject undefined. Never provide a principal at server startup.
 * A Reference models absent authentication without a fake construction-time
 * identity when Effect registers toolkit handlers. MCP client IDs are unrelated.
 */
export const CurrentAccess = /* @__PURE__ */ Context.Reference<Access | undefined>(
  "effect-auth/OAuthServer/CurrentAccess",
  { defaultValue: () => undefined },
);

/** Linearizable, standalone commits. Never retry an ambiguous insert or CAS.
 * Revoke must atomically disable the record, including against concurrent CAS.
 * Grant IDs must never be reused. Retain records through expiresAtMillis;
 * only then may they be deleted.
 */
export class Persistence extends Context.Service<Persistence, PersistenceService<SubjectId>>()(
  "effect-auth/OAuthServer/Persistence",
) {}

/** Application-owned prior approval for an exact OpenID client, callback and
 * claims. Called only after verifying the current browser authentication.
 * Explicit consent/account-selection prompts always remain interactive.
 */
export class OpenIdConsent extends Context.Service<
  OpenIdConsent,
  OpenIdConsentService<SubjectId>
>()("effect-auth/OAuthServer/OpenIdConsent") {
  static readonly default = OpenIdConsent.of(defaultOpenIdConsent<SubjectId>());

  /** Require interactive consent; no client or scope has implicit approval. */
  static readonly defaultLayer = Layer.succeed(OpenIdConsent, OpenIdConsent.default);
}

export interface Consent extends ServerConsent<SubjectId> {}

/** Render trusted consent metadata. Escape all displayed values and preserve the
 * POST action, csrf field and approve/deny decisions. Scripts are forbidden;
 * styles, fonts and images may load from the authorization server's own origin.
 */
export class ConsentRenderer extends Context.Service<
  ConsentRenderer,
  ConsentRendererService<SubjectId>
>()("effect-auth/OAuthServer/ConsentRenderer") {
  static readonly default = ConsentRenderer.of(defaultConsentRenderer<SubjectId>());

  /** Plain HTML consent; it does not remember consent or sign users in. */
  static readonly defaultLayer = Layer.succeed(ConsentRenderer, ConsentRenderer.default);
}

const binding: ServerBinding<typeof SubjectId, Persistence, ConsentRenderer, OpenIdConsent> = {
  subject: SubjectId,
  cookiePrefix: "yielded",
  onFailure: (cause) => reportAuthFailure("http", cause),
  reportedDefect: () => ReportedOperationDefect.make({}),
  Persistence,
  CurrentAccess,
  ConsentRenderer,
  OpenIdConsent,
};

/** Authorization-code server for MCP/resource authorization.
 * Declared scopes retain their branded literal types throughout the server.
 * The optional Authorization service decides scopes and claims at each issue.
 */
export const make = <const Id extends string, const S extends ReadonlyArray<OAuthScope.OAuthScope>>(
  id: Id,
  input: { readonly scopes: S },
) => makeOAuthServer(id, input, binding);

/** Registered-client OpenID Connect code flow with PKCE, RS256 and explicit consent.
 * Standard OpenID scopes are included alongside application scopes.
 * Applications own authentication, current session validity and profile disclosure.
 * Resource JWTs and rotating refresh tokens are opt-in. Clients are static or come
 * from the Clients service; registration endpoints and front/back-channel logout
 * are not provided.
 */
export const makeOpenId = <
  const Id extends string,
  const S extends ReadonlyArray<OAuthScope.OAuthScope> = readonly [],
>(
  id: Id,
  options: { readonly scopes?: S } = {},
) => makeOpenIdServer(id, options, binding);

export interface OpenIdIdentity<
  Scope extends OAuthScope.OAuthScope = OAuthScope.OAuthScope,
> extends ServerOpenIdIdentity<Scope, SubjectId> {}

interface VerifiedAccessToken<Scope extends OAuthScope.OAuthScope> {
  readonly verify: (
    credential: Redacted.Redacted<string>,
  ) => Effect.Effect<Access<Scope>, InvalidToken | Unavailable>;
  /** Verified protocol fields for an issuer checking its durable grant version. */
  readonly decode: (credential: Redacted.Redacted<string>) => Effect.Effect<
    {
      readonly claims: AccessTokenClaims<SubjectId>;
      readonly access: Access<Scope>;
    },
    InvalidToken | Unavailable
  >;
}

/** Verify offline with trusted public keys. Revocation and permission changes
 * take effect at token expiry; use short access lifetimes and renew through the issuer.
 * Retains only the signature service; verification uses the caller's clock and context.
 * Declared scopes narrow access only after every token scope passes validation.
 */
export function makeAccessTokenVerifier<const S extends ReadonlyArray<OAuthScope.OAuthScope>>(
  options: AccessTokenVerifierOptions & { readonly scopes: S },
): Effect.Effect<VerifiedAccessToken<S[number]>, ConfigurationError, Signature.Signature>;

export function makeAccessTokenVerifier(
  options: AccessTokenVerifierOptions,
): Effect.Effect<
  VerifiedAccessToken<OAuthScope.OAuthScope>,
  ConfigurationError,
  Signature.Signature
>;

export function makeAccessTokenVerifier(options: AccessTokenVerifierOptions) {
  return makeLocalVerifier(
    options,
    options.scopes === undefined ? Scope : Schema.Literals(options.scopes),
    SubjectId,
  );
}

/** Verify with the supplied Jwks service, for example Jwks.layerRemote from
 * effect/jose. Captures only Jwks and Signature.Signature; the caller's clock and context
 * still govern verification. Retain the resolver's owning Scope while using the
 * verifier. Remote key failures become Unavailable; invalid tokens remain InvalidToken.
 *
 * The host configures the trusted key endpoint and owns its platform lifetime.
 * On Workers, retain the bounded verification with waitUntil and await its native
 * Promise in each request. Do not tie that retained verification to request abort.
 * Revocation and permission changes take effect at access-token expiry.
 */
export function makeAccessTokenVerifierWithKeySet<
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
>(
  options: AccessTokenVerifierWithKeySetOptions & { readonly scopes: S },
): Effect.Effect<
  VerifiedAccessToken<S[number]>,
  ConfigurationError,
  Signature.Signature | Jwks.Jwks
>;

export function makeAccessTokenVerifierWithKeySet(
  options: AccessTokenVerifierWithKeySetOptions,
): Effect.Effect<
  VerifiedAccessToken<OAuthScope.OAuthScope>,
  ConfigurationError,
  Signature.Signature | Jwks.Jwks
>;

export function makeAccessTokenVerifierWithKeySet(options: AccessTokenVerifierWithKeySetOptions) {
  return makeVerifier(
    options,
    options.scopes === undefined ? Scope : Schema.Literals(options.scopes),
    SubjectId,
  );
}

export type { OpenIdOptions, Options } from "./oauth/server/server";
export type { IdentitySigningKeys } from "./oauth/server/openid";
export { OpenIdAuthorizationResult } from "./oauth/server/authorization";

export type {
  AccessTokenVerifierOptions,
  AccessTokenVerifierWithKeySetOptions,
} from "./oauth/server/access-token";

export {
  AccessClaims,
  OpenIdProfile,
  AssertionReceipt,
  Client,
  ConfigurationError,
  InvalidToken,
  Unavailable,
} from "./oauth/server/models";
