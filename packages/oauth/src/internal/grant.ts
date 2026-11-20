import * as Effect from "effect/Effect";
import * as Predicate from "effect/Predicate";

import type * as Grant from "../Grant.ts";
import type * as OAuthError from "../OAuthError.ts";
import * as V from "./validation.ts";

export const TypeId = "~effect/oauth/Grant" as const;

export interface ResolvedGrant {
  readonly grantType: string;
  /** Parameters serialized ahead of `grant_type` (extras and `resource` entries). */
  readonly leadingParameters: ReadonlyArray<readonly [string, string]>;
  /** Parameters serialized after `grant_type` (`code`, `refresh_token`, `scope`, etc.). */
  readonly trailingParameters: ReadonlyArray<readonly [string, string]>;
  readonly issuer?: string | undefined;
  readonly clientId?: string | undefined;
}

export const validators = new WeakMap<
  Grant.Grant,
  () => Effect.Effect<ResolvedGrant, OAuthError.OAuthError>
>();

export const isGrant = (u: unknown): u is Grant.Grant =>
  Predicate.isObject(u) && Predicate.hasProperty(u, TypeId) && validators.has(u as Grant.Grant);

export const resolveGrant = (
  grant: Grant.Grant,
): Effect.Effect<ResolvedGrant, OAuthError.OAuthError> => {
  const validate = Predicate.isObject(grant) ? validators.get(grant) : undefined;

  return validate === undefined
    ? Effect.fail(V.invalidArgument("Invalid OAuth grant"))
    : validate();
};
