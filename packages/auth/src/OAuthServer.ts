import * as Schema from "effect/Schema";

import { reportAuthFailure, ReportedOperationDefect } from "./internal/diagnostics";
import {
  makeLocalVerifierCore,
  makeVerifierCore,
  type AccessTokenVerifierOptions as ServerAccessTokenVerifierOptions,
  type AccessTokenVerifierWithKeySetOptions as ServerAccessTokenVerifierWithKeySetOptions,
} from "./oauth/server/access-token";
import {
  makeAccessSchema,
  makeAuthenticationSchema,
  Scope,
  type Access as ServerAccess,
  type Authentication as ServerAuthentication,
} from "./oauth/server/models";
import {
  makeCore,
  makeOpenIdCore,
  type FailureReporter,
  type OpenIdIdentity as ServerOpenIdIdentity,
  type ServerDefaults,
} from "./oauth/server/server";
import type * as OAuthScope from "./OAuthScope";
import { SubjectId } from "./Schema";

const authDefaults: ServerDefaults = {
  cookiePrefix: "yielded",
  onFailure: (cause) => reportAuthFailure("http", cause),
  reportedDefect: () => ReportedOperationDefect.make({}),
};

/** Authorization-code server for MCP/resource authorization.
 * Declared scopes retain their branded literal types throughout the server.
 * The optional Authorization service decides scopes and claims at each issue.
 * Defaults subjects to `@yielded/auth`'s `SubjectId`, cookies to `yielded-`,
 * and unexpected boundary failures to Yielded Auth diagnostics.
 */
export function make<
  const Id extends string,
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
  Subject extends string,
>(
  id: Id,
  input: {
    readonly scopes: S;
    readonly subject: Schema.Codec<Subject, string>;
    readonly onFailure?: FailureReporter | undefined;
  },
): ReturnType<typeof makeCore<Id, S, Subject>>;

export function make<const Id extends string, const S extends ReadonlyArray<OAuthScope.OAuthScope>>(
  id: Id,
  input: {
    readonly scopes: S;
    readonly subject?: undefined;
    readonly onFailure?: FailureReporter | undefined;
  },
): ReturnType<typeof makeCore<Id, S, SubjectId>>;

export function make<
  const Id extends string,
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
  Subject extends string,
>(
  id: Id,
  input: {
    readonly scopes: S;
    readonly subject?: Schema.Codec<Subject, string> | undefined;
    readonly onFailure?: FailureReporter | undefined;
  },
) {
  const onFailure = input.onFailure ?? authDefaults.onFailure;

  return input.subject === undefined
    ? makeCore(id, { scopes: input.scopes, subject: SubjectId, onFailure }, authDefaults)
    : makeCore(id, { scopes: input.scopes, subject: input.subject, onFailure }, authDefaults);
}

/** Registered-client OpenID Connect code flow with PKCE, RS256 and explicit consent.
 * Standard OpenID scopes are included alongside application scopes.
 * Applications own authentication, current session validity and profile disclosure.
 * Resource JWTs and rotating refresh tokens are opt-in. Clients are static or come
 * from the Clients service; registration endpoints and front/back-channel logout
 * are not provided.
 */
export function makeOpenId<
  const Id extends string,
  const S extends ReadonlyArray<OAuthScope.OAuthScope> = readonly [],
  Subject extends string = SubjectId,
>(
  id: Id,
  options: {
    readonly scopes?: S | undefined;
    readonly subject: Schema.Codec<Subject, string>;
    readonly onFailure?: FailureReporter | undefined;
  },
): ReturnType<typeof makeOpenIdCore<Id, S, Subject>>;

export function makeOpenId<
  const Id extends string,
  const S extends ReadonlyArray<OAuthScope.OAuthScope> = readonly [],
>(
  id: Id,
  options?: {
    readonly scopes?: S | undefined;
    readonly subject?: undefined;
    readonly onFailure?: FailureReporter | undefined;
  },
): ReturnType<typeof makeOpenIdCore<Id, S, SubjectId>>;

export function makeOpenId<
  const Id extends string,
  const S extends ReadonlyArray<OAuthScope.OAuthScope> = readonly [],
  Subject extends string = SubjectId,
>(
  id: Id,
  options: {
    readonly scopes?: S | undefined;
    readonly subject?: Schema.Codec<Subject, string> | undefined;
    readonly onFailure?: FailureReporter | undefined;
  } = {},
) {
  const onFailure = options.onFailure ?? authDefaults.onFailure;

  return options.subject === undefined
    ? makeOpenIdCore(id, { scopes: options.scopes, subject: SubjectId, onFailure }, authDefaults)
    : makeOpenIdCore(
        id,
        { scopes: options.scopes, subject: options.subject, onFailure },
        authDefaults,
      );
}

export type OpenIdIdentity<
  Scope extends OAuthScope.OAuthScope = OAuthScope.OAuthScope,
  Subject extends string = SubjectId,
> = ServerOpenIdIdentity<Scope, Subject>;

export type AccessTokenVerifierWithKeySetOptions<Subject extends string = SubjectId> =
  ServerAccessTokenVerifierWithKeySetOptions<Subject>;

export type AccessTokenVerifierOptions<Subject extends string = SubjectId> =
  ServerAccessTokenVerifierOptions<Subject>;

/** Verify offline with trusted public keys. Revocation and permission changes
 * take effect at token expiry; use short access lifetimes and renew through the issuer.
 * Retains only the signature service; verification uses the caller's clock and context.
 * Declared scopes narrow access only after every token scope passes validation.
 */
export function makeAccessTokenVerifier<
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
  Subject extends string,
>(
  options: AccessTokenVerifierOptions<Subject> & {
    readonly scopes: S;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeLocalVerifierCore<S[number], Subject>>;

export function makeAccessTokenVerifier<const S extends ReadonlyArray<OAuthScope.OAuthScope>>(
  options: AccessTokenVerifierOptions<SubjectId> & {
    readonly scopes: S;
    readonly subject?: undefined;
  },
): ReturnType<typeof makeLocalVerifierCore<S[number], SubjectId>>;

export function makeAccessTokenVerifier<Subject extends string>(
  options: AccessTokenVerifierOptions<Subject> & {
    readonly scopes?: undefined;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeLocalVerifierCore<OAuthScope.OAuthScope, Subject>>;

export function makeAccessTokenVerifier(
  options: AccessTokenVerifierOptions<SubjectId>,
): ReturnType<typeof makeLocalVerifierCore<OAuthScope.OAuthScope, SubjectId>>;

export function makeAccessTokenVerifier(options: ServerAccessTokenVerifierOptions<string>) {
  return makeLocalVerifierCore(
    options,
    options.scopes === undefined ? Scope : Schema.Literals(options.scopes),
    options.subject ?? SubjectId,
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
  Subject extends string,
>(
  options: AccessTokenVerifierWithKeySetOptions<Subject> & {
    readonly scopes: S;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeVerifierCore<S[number], Subject>>;

export function makeAccessTokenVerifierWithKeySet<
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
>(
  options: AccessTokenVerifierWithKeySetOptions<SubjectId> & {
    readonly scopes: S;
    readonly subject?: undefined;
  },
): ReturnType<typeof makeVerifierCore<S[number], SubjectId>>;

export function makeAccessTokenVerifierWithKeySet<Subject extends string>(
  options: AccessTokenVerifierWithKeySetOptions<Subject> & {
    readonly scopes?: undefined;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeVerifierCore<OAuthScope.OAuthScope, Subject>>;

export function makeAccessTokenVerifierWithKeySet(
  options: AccessTokenVerifierWithKeySetOptions<SubjectId>,
): ReturnType<typeof makeVerifierCore<OAuthScope.OAuthScope, SubjectId>>;

export function makeAccessTokenVerifierWithKeySet(
  options: ServerAccessTokenVerifierWithKeySetOptions<string>,
) {
  return makeVerifierCore(
    options,
    options.scopes === undefined ? Scope : Schema.Literals(options.scopes),
    options.subject ?? SubjectId,
  );
}

export const Access = /* @__PURE__ */ makeAccessSchema(Scope, SubjectId);

export type Access<
  Scope extends OAuthScope.OAuthScope = OAuthScope.OAuthScope,
  Subject extends string = SubjectId,
> = ServerAccess<Scope, Subject>;

export const Authentication = /* @__PURE__ */ makeAuthenticationSchema(SubjectId);

export type Authentication<Subject extends string = SubjectId> = ServerAuthentication<Subject>;

export type { FailureReporter, OpenIdOptions, Options } from "./oauth/server/server";
export type { IdentitySigningKeys } from "./oauth/server/openid";
export { ConsentRenderer, OpenIdConsent, type Consent } from "./oauth/server/consent";
export { OpenIdAuthorizationResult } from "./oauth/server/authorization";

export {
  AccessClaims,
  OpenIdProfile,
  AssertionReceipt,
  Client,
  ConfigurationError,
  CurrentAccess,
  InvalidToken,
  Persistence,
  Record,
  Unavailable,
  type SigningKeyring,
} from "./oauth/server/models";
