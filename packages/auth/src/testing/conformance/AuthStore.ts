import { DateTime, Duration, Effect, Schema } from "effect";
import { TestClock } from "effect/testing";

import { AuthStore } from "../../AuthStore";
import {
  type Email,
  ChallengeId,
  ConsumeChallenge,
  ConsumeRegistration,
  KeyId,
  NewChallenge,
  NewRegistration,
  RegistrationId,
} from "../../Schema";
import { check, emailOf, expectFailure, otpDigestOf, tokenDigestOf, uuidOf } from "./support";

// Pure store-contract checks for `AuthStore` adapters. Run each case with
// `it.effect` (TestClock required) against the adapter's layer.

export interface AuthStoreConformanceCase {
  readonly name: string;
  readonly run: Effect.Effect<void, never, AuthStore>;
}

const decodeChallengeId = Schema.decodeSync(ChallengeId);
const decodeRegistrationId = Schema.decodeSync(RegistrationId);

const conformanceKeyId = Schema.decodeSync(KeyId)("conformance-key");

let uniqueId = 0;

const makeChallenge = (options: {
  readonly email: Email;
  readonly token: string;
  readonly otp: string;
  readonly attemptLimit?: number;
  readonly lifetime?: Duration.Duration;
  readonly resendCooldown?: Duration.Duration;
}): Effect.Effect<NewChallenge> =>
  Effect.map(DateTime.now, (now) =>
    NewChallenge.make({
      challengeId: decodeChallengeId(uuidOf(++uniqueId)),
      tokenDigest: tokenDigestOf(options.token),
      email: options.email,
      purpose: "sign-in",
      otpDigest: otpDigestOf(options.otp),
      otpKeyId: conformanceKeyId,
      issuedAt: now,
      expiresAt: DateTime.addDuration(now, options.lifetime ?? Duration.minutes(10)),
      attemptLimit: options.attemptLimit ?? 5,
      resendCooldown: options.resendCooldown ?? Duration.seconds(60),
    }),
  );

const consume = (token: string, otp: string) =>
  Effect.flatMap(AuthStore, (store) =>
    store.consumeChallenge(
      ConsumeChallenge.make({
        tokenDigest: tokenDigestOf(token),
        otpDigests: { [conformanceKeyId]: otpDigestOf(otp) },
      }),
    ),
  );

const makeRegistration = (options: {
  readonly email: Email;
  readonly token: string;
  readonly lifetime?: Duration.Duration;
}): Effect.Effect<NewRegistration> =>
  Effect.map(DateTime.now, (now) =>
    NewRegistration.make({
      registrationId: decodeRegistrationId(uuidOf(++uniqueId)),
      tokenDigest: tokenDigestOf(options.token),
      email: options.email,
      purpose: "registration",
      issuedAt: now,
      expiresAt: DateTime.addDuration(now, options.lifetime ?? Duration.minutes(15)),
    }),
  );

const conformanceCase = <CaseError>(
  name: string,
  run: Effect.Effect<void, CaseError, AuthStore>,
): AuthStoreConformanceCase => ({ name, run: Effect.orDie(run) });

export const authStoreConformanceCases: ReadonlyArray<AuthStoreConformanceCase> = [
  conformanceCase(
    "expiry boundaries are deterministic",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const before = emailOf("expiry-before");

      yield* store.issueChallenge(
        yield* makeChallenge({ email: before, token: "expiry-1", otp: "11111111" }),
      );
      yield* TestClock.adjust(Duration.subtract(Duration.minutes(10), Duration.millis(1)));
      yield* consume("expiry-1", "11111111");

      const at = emailOf("expiry-at");

      yield* store.issueChallenge(
        yield* makeChallenge({ email: at, token: "expiry-2", otp: "22222222" }),
      );
      yield* TestClock.adjust(Duration.minutes(10));
      yield* expectFailure(
        consume("expiry-2", "22222222"),
        "EmailOtpRejected",
        "a challenge must be rejected once its expiry instant is reached",
      );
    }),
  ),

  conformanceCase(
    "wrong attempts increment and exhaust the configured budget",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const email = emailOf("budget");

      yield* store.issueChallenge(
        yield* makeChallenge({ email, token: "budget-1", otp: "11111111", attemptLimit: 3 }),
      );
      for (let attempt = 0; attempt < 3; attempt++) {
        yield* expectFailure(
          consume("budget-1", "99999999"),
          "EmailOtpRejected",
          "a wrong code must fail",
        );
      }
      yield* expectFailure(
        consume("budget-1", "11111111"),
        "EmailOtpRejected",
        "an exhausted challenge must reject even the correct code",
      );
    }),
  ),

  conformanceCase(
    "resend supersedes prior challenges without resetting the rolling budget",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const email = emailOf("supersede");

      yield* store.issueChallenge(
        yield* makeChallenge({ email, token: "supersede-1", otp: "11111111", attemptLimit: 3 }),
      );
      yield* expectFailure(consume("supersede-1", "00000000"), "EmailOtpRejected", "wrong");
      yield* expectFailure(consume("supersede-1", "00000001"), "EmailOtpRejected", "wrong");
      yield* TestClock.adjust(Duration.seconds(61));
      yield* store.issueChallenge(
        yield* makeChallenge({ email, token: "supersede-2", otp: "22222222", attemptLimit: 3 }),
      );
      yield* expectFailure(
        consume("supersede-1", "11111111"),
        "EmailOtpRejected",
        "a superseded challenge must reject its own correct code",
      );
      yield* expectFailure(
        consume("supersede-2", "00000002"),
        "EmailOtpRejected",
        "wrong code on the replacement challenge",
      );
      yield* expectFailure(
        consume("supersede-2", "22222222"),
        "EmailOtpRejected",
        "the rolling budget must carry across resends and exhaust the replacement",
      );
    }),
  ),

  conformanceCase(
    "parallel valid verification produces exactly one success",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const email = emailOf("parallel-challenge");

      yield* store.issueChallenge(
        yield* makeChallenge({ email, token: "parallel-1", otp: "11111111" }),
      );

      const exits = yield* Effect.all(
        Array.from({ length: 8 }, () => Effect.exit(consume("parallel-1", "11111111"))),
        { concurrency: "unbounded" },
      );

      const successes = exits.filter((exit) => exit._tag === "Success").length;

      yield* check(successes === 1, `expected exactly one success, saw ${successes}`);
    }),
  ),

  conformanceCase(
    "a consumed challenge cannot be replayed",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const email = emailOf("replay-challenge");

      yield* store.issueChallenge(
        yield* makeChallenge({ email, token: "replay-1", otp: "11111111" }),
      );
      yield* consume("replay-1", "11111111");
      yield* expectFailure(
        consume("replay-1", "11111111"),
        "EmailOtpRejected",
        "a consumed challenge must reject replays",
      );
    }),
  ),

  conformanceCase(
    "issuance enforces the resend cooldown with a typed error",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const email = emailOf("cooldown");

      yield* store.issueChallenge(
        yield* makeChallenge({ email, token: "cooldown-1", otp: "11111111" }),
      );
      yield* expectFailure(
        Effect.flatMap(
          makeChallenge({ email, token: "cooldown-2", otp: "22222222" }),
          (challenge) => store.issueChallenge(challenge),
        ),
        "AuthRateLimited",
        "issuing within the cooldown must be rate limited",
      );
      yield* TestClock.adjust(Duration.seconds(60));
      yield* Effect.flatMap(
        makeChallenge({ email, token: "cooldown-3", otp: "33333333" }),
        (challenge) => store.issueChallenge(challenge),
      );
    }),
  ),

  conformanceCase(
    "pending registrations are single-use and expire",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const email = emailOf("registration");

      yield* store.issueRegistration(yield* makeRegistration({ email, token: "registration-1" }));
      const registration = yield* store.inspectRegistration(tokenDigestOf("registration-1"));

      yield* check(registration.email === email, "inspect must return the registration's email");
      yield* store.consumeRegistration(
        ConsumeRegistration.make({ tokenDigest: tokenDigestOf("registration-1") }),
      );
      yield* expectFailure(
        store.inspectRegistration(tokenDigestOf("registration-1")),
        "InvalidRegistration",
        "a consumed registration must not be inspectable",
      );
      yield* expectFailure(
        store.consumeRegistration(
          ConsumeRegistration.make({ tokenDigest: tokenDigestOf("registration-1") }),
        ),
        "InvalidRegistration",
        "a consumed registration must not be consumable again",
      );

      yield* store.issueRegistration(yield* makeRegistration({ email, token: "registration-2" }));
      yield* TestClock.adjust(Duration.minutes(15));
      yield* expectFailure(
        store.inspectRegistration(tokenDigestOf("registration-2")),
        "InvalidRegistration",
        "an expired registration must be rejected",
      );
    }),
  ),

  conformanceCase(
    "parallel registration consumption produces exactly one success",
    Effect.gen(function* () {
      const store = yield* AuthStore;
      const email = emailOf("parallel-registration");

      yield* store.issueRegistration(
        yield* makeRegistration({ email, token: "parallel-registration-1" }),
      );

      const exits = yield* Effect.all(
        Array.from({ length: 8 }, () =>
          Effect.exit(
            store.consumeRegistration(
              ConsumeRegistration.make({ tokenDigest: tokenDigestOf("parallel-registration-1") }),
            ),
          ),
        ),
        { concurrency: "unbounded" },
      );

      const successes = exits.filter((exit) => exit._tag === "Success").length;

      yield* check(successes === 1, `expected exactly one success, saw ${successes}`);
    }),
  ),

  conformanceCase(
    "unknown tokens fail with typed internal rejections",
    Effect.gen(function* () {
      const store = yield* AuthStore;

      yield* expectFailure(
        consume("never-issued", "11111111"),
        "EmailOtpRejected",
        "an unknown challenge token must map to the internal OTP rejection",
      );
      yield* expectFailure(
        store.inspectRegistration(tokenDigestOf("never-issued")),
        "InvalidRegistration",
        "an unknown registration token must map to the generic registration error",
      );
    }),
  ),
];
