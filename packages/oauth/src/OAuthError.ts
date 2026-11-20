/**
 * The `OAuthError` returned by the OAuth and OpenID Connect modules, and the
 * closed set of reasons it carries.
 *
 * Every failure is one `OAuthError` whose `reason` identifies what failed:
 * `InvalidArgument`, `ClientAuthFailed`, `DiscoveryFailed`, `TransportFailed`,
 * `InvalidResponse`, `CallbackRejected`, `AuthorizationDenied`,
 * `EndpointError`, or `TokenVerificationFailed`.
 *
 * **Gotchas**
 *
 * The error is not serializable, so it cannot cross an RPC or HttpApi boundary
 * without explicit mapping. Reasons never embed raw tokens, claims, or
 * unvalidated provider text.
 *
 * @stability unstable
 * @since 4.1.4
 */
import * as Data from "effect/Data";
import * as Predicate from "effect/Predicate";

const TypeId = "~effect/oauth/OAuthError" as const;
const ReasonTypeId = "~effect/oauth/OAuthError/Reason" as const;

/**
 * Closed set of standard OAuth 2.0 / OIDC error codes returned by protocol
 * endpoints. Unrecognized codes map to `"other"` with a bounded `rawCode`.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "unsupported_response_type"
  | "unsupported_token_type"
  | "invalid_scope"
  | "invalid_target"
  | "invalid_token"
  | "insufficient_scope"
  | "access_denied"
  | "interaction_required"
  | "login_required"
  | "account_selection_required"
  | "consent_required"
  | "temporarily_unavailable"
  | "server_error"
  | "other";

/**
 * Reason for a caller-supplied argument, option, or local configuration value
 * rejected before any remote request is dispatched.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class InvalidArgument extends Data.TaggedError("InvalidArgument")<{
  readonly description: string;
  readonly cause?: unknown;
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return this.description;
  }
}

/**
 * Reason for a failure preparing client authentication material before an
 * authenticated endpoint request is sent.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class ClientAuthFailed extends Data.TaggedError("ClientAuthFailed")<{
  readonly description: string;
  readonly cause?: unknown;
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return this.description;
  }
}

/**
 * Reason for an authorization-server discovery document that failed validation,
 * issuer verification, or local supplementation.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class DiscoveryFailed extends Data.TaggedError("DiscoveryFailed")<{
  readonly description: string;
  readonly cause?: unknown;
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return this.description;
  }
}

/**
 * Reason for an HTTP transport, timeout, redirect, size-limit, closed-scope,
 * or 5xx upstream failure. For stateful exchanges, the remote outcome is
 * indeterminate and must not be automatically retried.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class TransportFailed extends Data.TaggedError("TransportFailed")<{
  readonly endpoint: "discovery" | "jwks" | "token" | "userinfo" | "revocation";
  readonly status?: number | undefined;
  readonly description: string;
  readonly cause?: unknown;
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return this.status === undefined
      ? `${this.endpoint}: ${this.description}`
      : `${this.endpoint} (${this.status}): ${this.description}`;
  }
}

/**
 * Reason for an upstream endpoint response whose status, content type, or
 * payload does not satisfy the protocol contract.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class InvalidResponse extends Data.TaggedError("InvalidResponse")<{
  readonly endpoint: "token" | "userinfo" | "revocation";
  readonly status: number;
  readonly description: string;
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return `${this.endpoint} (${this.status}): ${this.description}`;
  }
}

/**
 * Reason for an authorization callback rejected before or during transaction
 * binding validation. Unbound callback rejections must leave pending flows
 * untouched.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class CallbackRejected extends Data.TaggedError("CallbackRejected")<{
  readonly reason:
    | "invalidTransport"
    | "duplicateParameter"
    | "unexpectedParameter"
    | "missingState"
    | "stateMismatch"
    | "invalidParameters"
    | "missingIssuer"
    | "issuerMismatch";
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return `The OAuth callback was rejected: ${this.reason}`;
  }
}

/**
 * Reason for a bound authorization callback where the user or authorization
 * server returned `error=access_denied`.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class AuthorizationDenied extends Data.TaggedError("AuthorizationDenied")<{}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return "The authorization request was denied";
  }
}

/**
 * Reason for a conformant protocol error returned by an authorization, token,
 * userinfo, or revocation endpoint.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class EndpointError extends Data.TaggedError("EndpointError")<{
  readonly endpoint: "authorization" | "token" | "userinfo" | "revocation";
  readonly code: OAuthErrorCode;
  readonly rawCode?: string | undefined;
  readonly status?: number | undefined;
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return this.status === undefined
      ? `${this.endpoint} endpoint error: ${this.code}`
      : `${this.endpoint} endpoint error (${this.status}): ${this.code}`;
  }
}

/**
 * Reason for an ID token or UserInfo response that failed cryptographic,
 * header, claim, freshness, hash, continuity, or subject verification.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class TokenVerificationFailed extends Data.TaggedError("TokenVerificationFailed")<{
  readonly reason:
    | "malformed"
    | "algorithm"
    | "key"
    | "signature"
    | "typ"
    | "expired"
    | "notYetValid"
    | "claim"
    | "issuer"
    | "audience"
    | "nonce"
    | "maxAge"
    | "hash"
    | "continuity"
    | "subjectMismatch";
  readonly cause?: unknown;
}> {
  /**
   * Marks this value as an `OAuthError` reason for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [ReasonTypeId] = ReasonTypeId;

  override get message(): string {
    return `Token verification failed: ${this.reason}`;
  }
}

/**
 * Union of the reasons carried by `OAuthError`.
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export type OAuthErrorReason =
  | InvalidArgument
  | ClientAuthFailed
  | DiscoveryFailed
  | TransportFailed
  | InvalidResponse
  | CallbackRejected
  | AuthorizationDenied
  | EndpointError
  | TokenVerificationFailed;

/**
 * Error returned by the OAuth and OpenID Connect protocol modules.
 *
 * @see {@link isOAuthError} for narrowing unknown values
 *
 * @stability unstable
 * @category errors
 * @since 4.1.4
 */
export class OAuthError extends Data.TaggedError("OAuthError")<{
  readonly reason: OAuthErrorReason;
}> {
  /**
   * Marks this value as an `OAuthError` for runtime guards.
   *
   * @since 4.1.4
   */
  readonly [TypeId] = TypeId;

  /**
   * The reason's cause, when it has one.
   *
   * @since 4.1.4
   */
  override readonly cause: unknown = "cause" in this.reason ? this.reason.cause : undefined;

  override get message(): string {
    return this.reason.message;
  }
}

/**
 * Checks whether a value is an `OAuthError`.
 *
 * @stability unstable
 * @category guards
 * @since 4.1.4
 */
export const isOAuthError = (u: unknown): u is OAuthError => Predicate.hasProperty(u, TypeId);

/**
 * Checks whether a value is one of the reasons carried by `OAuthError`.
 *
 * @stability unstable
 * @category guards
 * @since 4.1.4
 */
export const isOAuthErrorReason = (u: unknown): u is OAuthErrorReason =>
  Predicate.hasProperty(u, ReasonTypeId);
