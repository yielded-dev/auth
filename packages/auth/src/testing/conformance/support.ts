import { Effect, Schema } from "effect";

import { Email, OtpDigest, SubjectId, TokenDigest } from "../../Schema";

// Shared fabrication and assertion helpers for the store conformance suites.
// Digests and identifiers are opaque strings to every store, so the suites
// fabricate them directly and never need a codec.

const decodeEmail = Schema.decodeSync(Email);
const decodeTokenDigest = Schema.decodeSync(TokenDigest);
const decodeOtpDigest = Schema.decodeSync(OtpDigest);

export const decodeSubjectId = Schema.decodeSync(SubjectId);

export const emailOf = (name: string) => decodeEmail(`${name}@conformance.test`);
export const tokenDigestOf = (token: string) => decodeTokenDigest(`token-digest:${token}`);
export const otpDigestOf = (otp: string) => decodeOtpDigest(`otp-digest:${otp}`);

export const uuidOf = (index: number) =>
  `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;

export const check = (condition: boolean, message: string): Effect.Effect<void> =>
  condition ? Effect.void : Effect.die(new Error(`Store conformance violation: ${message}`));

export const expectFailure = <A, E extends { readonly _tag: string }, R>(
  effect: Effect.Effect<A, E, R>,
  tag: E["_tag"],
  message: string,
): Effect.Effect<void, never, R> =>
  Effect.exit(effect).pipe(
    Effect.flatMap((exit) =>
      check(
        exit._tag === "Failure" &&
          exit.cause.reasons.some((reason) => reason._tag === "Fail" && reason.error._tag === tag),
        message,
      ),
    ),
  );
