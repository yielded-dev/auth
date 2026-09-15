import { Effect, Encoding, Redacted, Result, Schema } from "effect";

import type { ProofDeliveryMessage } from "../proofs/delivery";
import { ProofReference } from "../proofs/models";
import { EmailConfigurationError, EmailRejected } from "./errors";

const secret = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/));
const payload = Schema.Struct({ reference: ProofReference, token: secret });
const codec = Schema.fromJsonString(payload);

const fragmentSchema = Schema.String.check(
  Schema.isMaxLength(4096),
  Schema.isPattern(/^#eal1\.[A-Za-z0-9_-]+$/),
);

/** Fixed configured HTTPS landing location. Mail vendors must preserve fragments
 * and disable click tracking/rewriting that leaks them into queries or logs.
 * The result remains Redacted because the URL fragment contains a bearer proof.
 */
export const makeMagicLinkRenderer = Effect.fn("makeMagicLinkRenderer")(function* (
  landing: string,
) {
  yield* Schema.decodeEffect(Schema.String.check(Schema.isMaxLength(2048)))(landing).pipe(
    Effect.mapError(() => EmailConfigurationError.make({})),
  );

  const url = yield* Effect.try({
    try: () => new URL(landing),
    catch: () => EmailConfigurationError.make({}),
  });

  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.href !== landing
  )
    return yield* EmailConfigurationError.make({});
  const target = url.href;

  return Effect.fn("MagicLink.render")(function* (message: ProofDeliveryMessage) {
    const encoded = yield* Schema.encodeEffect(codec)({
      reference: message.reference,
      token: Redacted.value(message.secret),
    }).pipe(Effect.mapError(() => EmailRejected.make({})));

    return Redacted.make(`${target}#eal1.${Encoding.encodeBase64Url(encoded)}`);
  });
});

/** Client-only extraction, without authentication side effects. Caller removes the
 * fragment immediately with history.replaceState, then waits for an intentional
 * action before same-origin CSRF-protected POST. Only reference/token are accepted;
 * flow, binder and return target come from the originating client's private state.
 */
export const parseMagicLinkFragment = Effect.fn("MagicLink.parseFragment")(function* (
  fragment: Redacted.Redacted<string>,
) {
  const raw = yield* Schema.decodeEffect(fragmentSchema)(Redacted.value(fragment)).pipe(
    Effect.mapError(() => EmailRejected.make({})),
  );

  const json = Result.getOrUndefined(Encoding.decodeBase64UrlString(raw.slice(6)));

  if (json === undefined) return yield* EmailRejected.make({});

  const decoded = yield* Schema.decodeEffect(codec)(json).pipe(
    Effect.mapError(() => EmailRejected.make({})),
  );

  return { reference: decoded.reference, secret: Redacted.make(decoded.token) };
});

/** Landing GET is static consumer UI: it must not call issue/attempt/complete or
 * redirect. Consumers choose their CSP script hashes/nonces if adding client code.
 */
export const magicLinkLandingHeaders = Object.freeze({
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
});
