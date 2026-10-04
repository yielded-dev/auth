import type { OAuthUnavailable } from "@yielded/auth/OAuth";
/* oxlint-disable no-explicit-any -- private adapter wraps only the Effect-valued semantic ports. */
import { Effect } from "effect";

import { unavailable } from "./oauth-state";

/** Snapshot before the first asynchronous owner/allocator step; closed bound
 * authorities reject before running even an application codec or inspector. */
export const capturedOAuthService = <
  S extends { [K in keyof S]: (...args: any[]) => Effect.Effect<any, OAuthUnavailable> },
>(
  service: S,
  inputs: { readonly [K in keyof S]: (input: any) => any },
  active: () => boolean,
  poison: () => void,
): S =>
  Object.freeze(
    Object.fromEntries(
      Object.entries(service).map(([key, method]) => [
        key,
        (input: any, prepare?: any) =>
          Effect.suspend(() => {
            if (!active()) return Effect.fail(unavailable());
            const retained = inputs[key as keyof S](input);

            return (method as (...args: any[]) => Effect.Effect<any, OAuthUnavailable>)(
              retained,
              prepare,
            );
          }).pipe(
            Effect.onExit((exit) =>
              Effect.sync(() => {
                if (exit._tag === "Failure") poison();
              }),
            ),
            Effect.catchDefect(() => Effect.fail(unavailable())),
          ),
      ]),
    ),
  ) as S;
