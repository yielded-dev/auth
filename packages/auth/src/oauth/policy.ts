import { Context, Duration, Layer } from "effect";

export interface OAuthPolicyShape {
  /** Lifetime of one authorization redirect's `state`. */
  readonly stateLifetime: Duration.Duration;
  /**
   * Access tokens are refreshed this long before their recorded expiry, so a
   * token handed to a caller does not expire mid-request.
   */
  readonly accessTokenRefreshMargin: Duration.Duration;
}

// Ten minutes comfortably covers a consent screen (with a possible provider
// sign-in in the middle) while keeping abandoned states short-lived.
export const defaultOAuthPolicy: OAuthPolicyShape = {
  stateLifetime: Duration.minutes(10),
  accessTokenRefreshMargin: Duration.minutes(1),
};

export const OAuthPolicy = Context.Reference<OAuthPolicyShape>("effect-auth/OAuthPolicy", {
  defaultValue: () => defaultOAuthPolicy,
});

/** Builds an OAuth policy layer by overriding the secure library defaults. */
export const layerOAuthPolicy = (overrides: Partial<OAuthPolicyShape> = {}) =>
  Layer.succeed(OAuthPolicy)({ ...defaultOAuthPolicy, ...overrides });
