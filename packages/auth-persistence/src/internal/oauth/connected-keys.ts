import type * as M from "@yielded/auth/OAuth";
import { Effect, Schema } from "effect";

import { digest, invariant, storage } from "./state";

export const strings = storage(Schema.Array(Schema.String));

const encoder = new TextEncoder();

const decoder = new TextDecoder("utf-8", { fatal: true });

export const key = Effect.fnUntraced(function* (domain: string, fields: ReadonlyArray<string>) {
  for (const value of fields) invariant(decoder.decode(encoder.encode(value)) === value);

  return "v1:" + (yield* digest(strings.encode([domain, ...fields])));
});

export const clientKey = (configuration: M.OAuthConnectedConfiguration) =>
  key("effect-auth/oauth-connected-client/v1", [
    configuration.provider,
    configuration.issuer,
    configuration.profile.clientRegistrationId,
  ]);

export const cohortKey = (client: string, identity: string) =>
  key("effect-auth/oauth-connected-cohort/v1", [client, identity]);

export const scopeKey = (provider: string, issuer: string) =>
  key("effect-auth/oauth-connected-provider-issuer/v1", [provider, issuer]).pipe(
    Effect.map((value) => "scope:" + value),
  );
