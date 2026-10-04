import * as OAuth from "@yielded/oauth/OAuth";
import { Effect, Redacted } from "effect";

import { OAuthProtocolRejected, OAuthUnavailable } from "../signInErrors";
import { DefiniteTokenRejection, type TokenCompatibility } from "./compatibility";

/** Provider-specific raw fields are inspected before the generic token projection. */
export const tokens = Effect.fn("OpenIdConnect.tokens")(function* (
  receipt: OAuth.TokenReceipt,
  compatibility: TokenCompatibility | undefined,
  input: Parameters<TokenCompatibility["inspectReceipt"]>[1],
) {
  if (compatibility !== undefined)
    yield* Effect.try({
      try: () =>
        compatibility.inspectReceipt({ ...receipt, body: Redacted.value(receipt.body) }, input),
      catch: (error) =>
        error instanceof DefiniteTokenRejection
          ? OAuthProtocolRejected.make({})
          : OAuthUnavailable.make({}),
    });

  return yield* OAuth.tokens(receipt).pipe(
    Effect.mapError((error) =>
      error._tag === "OAuthRejected" ? OAuthProtocolRejected.make({}) : OAuthUnavailable.make({}),
    ),
  );
});
