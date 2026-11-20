/**
 * Proof Key for Code Exchange (PKCE, RFC 7636) using the `S256` challenge
 * method.
 *
 * `generate` mints a 256-bit verifier and its SHA-256 base64url challenge.
 * `challenge` derives the `S256` challenge for an existing verifier.
 *
 * @stability unstable
 * @since 4.1.4
 */
import * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import * as OAuthError from "./OAuthError.ts";

const VerifierString = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9._~-]{43,128}$/));
const isVerifierString = Schema.is(VerifierString);

/**
 * Schema for an RFC 7636 PKCE code verifier (43 to 128 unreserved characters),
 * decoded into a `Redacted<string>`.
 *
 * @stability unstable
 * @category schemas
 * @since 4.1.4
 */
export const Verifier: Schema.RedactedFromValue<Schema.String> =
  Schema.RedactedFromValue(VerifierString);

/**
 * An RFC 7636 PKCE code verifier kept in `Redacted<string>`.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type Verifier = typeof Verifier.Type;

/**
 * Schema for an RFC 7636 `S256` PKCE code challenge (43 unpadded base64url
 * characters).
 *
 * @stability unstable
 * @category schemas
 * @since 4.1.4
 */
export const Challenge: Schema.String = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9_-]{43}$/),
);

/**
 * An RFC 7636 `S256` PKCE code challenge.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type Challenge = typeof Challenge.Type;

/**
 * A generated PKCE verifier and its derived `S256` challenge.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface Pair {
  readonly verifier: Redacted.Redacted<string>;
  readonly challenge: string;
}

/**
 * Generates a 256-bit PKCE verifier and its `S256` challenge.
 *
 * @stability unstable
 * @category pkce
 * @since 4.1.4
 */
export const generate: Effect.Effect<Pair, never, Digest.Digest | SecureRandom.SecureRandom> =
  Effect.gen(function* () {
    const random = yield* SecureRandom.SecureRandom;
    const digest = yield* Digest.Digest;
    const bytes = yield* random.randomBytes(32);

    if (bytes.length !== 32) {
      return yield* Effect.die(
        new RangeError("SecureRandom.randomBytes(32) returned an unexpected byte length"),
      );
    }

    const raw = Base64Url.encode(bytes);
    const hashed = yield* digest.digest(Digest.sha256, new TextEncoder().encode(raw));

    if (hashed.length !== 32) {
      return yield* Effect.die(new RangeError("Digest.sha256 returned an unexpected byte length"));
    }

    return {
      verifier: Redacted.make(raw),
      challenge: Base64Url.encode(hashed),
    };
  });

/**
 * Derives the RFC 7636 `S256` code challenge for a PKCE verifier.
 *
 * Fails with `OAuthError` (`InvalidArgument`) when the verifier is wiped or
 * does not match the RFC 7636 verifier grammar.
 *
 * @stability unstable
 * @category pkce
 * @since 4.1.4
 */
export const challenge: (
  verifier: string | Redacted.Redacted<string>,
) => Effect.Effect<string, OAuthError.OAuthError, Digest.Digest> = (verifier) =>
  Effect.suspend(() => {
    let raw: string;

    try {
      raw = Redacted.isRedacted(verifier) ? Redacted.value(verifier) : verifier;
    } catch (cause) {
      return Effect.fail(
        new OAuthError.OAuthError({
          reason: new OAuthError.InvalidArgument({
            description: "PKCE verifier is unavailable",
            cause,
          }),
        }),
      );
    }

    if (!isVerifierString(raw)) {
      return Effect.fail(
        new OAuthError.OAuthError({
          reason: new OAuthError.InvalidArgument({
            description: "PKCE verifier must be 43 to 128 unreserved RFC 7636 characters",
          }),
        }),
      );
    }

    return Digest.Digest.use((digest) =>
      Effect.flatMap(digest.digest(Digest.sha256, new TextEncoder().encode(raw)), (bytes) =>
        bytes.length === 32
          ? Effect.succeed(Base64Url.encode(bytes))
          : Effect.die(new RangeError("Digest.sha256 returned an unexpected byte length")),
      ),
    );
  });
