import type * as OAuthError from "@yielded/oauth/OAuthError";

import { OAuthProtocolRejected, OAuthUnavailable } from "../../signInErrors";
import { OpenIdConnectConfigurationError } from "./models";

export type OAuthOperation = "authorization_code" | "refresh_token" | "revocation";

export type OAuthPhase = "callback" | "preSend" | "token" | "idToken" | "userInfo" | "revocation";

export interface OAuthErrorContext {
  readonly operation: OAuthOperation;
  readonly phase: OAuthPhase;
}

export type OAuthCallbackOutcome =
  | { readonly _tag: "RejectRequest" }
  | { readonly _tag: "CancelFlow" }
  | { readonly _tag: "Unavailable" };

const postSignatureTokenFailures: ReadonlySet<OAuthError.TokenVerificationFailed["reason"]> =
  new Set([
    "typ",
    "expired",
    "notYetValid",
    "claim",
    "issuer",
    "audience",
    "nonce",
    "maxAge",
    "hash",
    "subjectMismatch",
  ]);

/** Classify an `@yielded/oauth` failure at installation / configuration time. */
export const classifyOAuthConfigurationError = (
  error: OAuthError.OAuthError,
): OpenIdConnectConfigurationError | OAuthUnavailable => {
  switch (error.reason._tag) {
    case "InvalidArgument":
    case "DiscoveryFailed":
      return OpenIdConnectConfigurationError.make({ reason: "metadata" });
    case "ClientAuthFailed":
    case "TransportFailed":
    case "InvalidResponse":
    case "CallbackRejected":
    case "AuthorizationDenied":
    case "EndpointError":
    case "TokenVerificationFailed":
      return OAuthUnavailable.make({});
  }
};

/** Classify an `@yielded/oauth` callback failure per the callback boundary. */
export const classifyOAuthCallbackError = (error: OAuthError.OAuthError): OAuthCallbackOutcome => {
  switch (error.reason._tag) {
    case "CallbackRejected":
      return { _tag: "RejectRequest" };
    case "AuthorizationDenied":
      return { _tag: "CancelFlow" };
    case "EndpointError":
      return error.reason.endpoint === "authorization"
        ? { _tag: "CancelFlow" }
        : { _tag: "Unavailable" };
    case "InvalidArgument":
    case "ClientAuthFailed":
    case "DiscoveryFailed":
    case "TransportFailed":
    case "InvalidResponse":
    case "TokenVerificationFailed":
      return { _tag: "Unavailable" };
  }
};

/** Classify an `@yielded/oauth` runtime failure by operation and execution phase.
 * Indeterminate post-send and post-rotation outcomes remain `OAuthUnavailable`
 * so callers never replay stateful grants or burn credentials on ambiguous faults. */
export function classifyOAuthError(
  error: OAuthError.OAuthError,
  context:
    | { readonly operation: OAuthOperation; readonly phase: "preSend" | "revocation" }
    | { readonly operation: "refresh_token"; readonly phase: "idToken" | "userInfo" },
): OAuthUnavailable;

export function classifyOAuthError(
  error: OAuthError.OAuthError,
  context: OAuthErrorContext,
): OAuthProtocolRejected | OAuthUnavailable;

export function classifyOAuthError(
  error: OAuthError.OAuthError,
  context: OAuthErrorContext,
): OAuthProtocolRejected | OAuthUnavailable {
  const { reason } = error;

  if (context.phase === "preSend" || context.phase === "revocation") {
    return OAuthUnavailable.make({});
  }

  if (
    context.phase === "token" &&
    (context.operation === "authorization_code" || context.operation === "refresh_token") &&
    reason._tag === "EndpointError" &&
    reason.endpoint === "token" &&
    reason.status === 400 &&
    reason.code === "invalid_grant"
  ) {
    return OAuthProtocolRejected.make({});
  }

  if (
    context.operation === "authorization_code" &&
    (context.phase === "idToken" || context.phase === "userInfo") &&
    reason._tag === "TokenVerificationFailed" &&
    postSignatureTokenFailures.has(reason.reason)
  ) {
    return OAuthProtocolRejected.make({});
  }

  return OAuthUnavailable.make({});
}
