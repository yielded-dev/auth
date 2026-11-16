import * as Cause from "effect/Cause";
import type * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";

import { LifecycleHooks } from "../hooks/LifecycleHooks";
import {
  type HookDenied,
  lifecycleEvent,
  lifecycleSnapshotEffect,
  LifecycleEventId,
} from "../hooks/models";
import { LoginIdentifier } from "../identity/models";
import { phoneFailure } from "./failure";
import { type PhoneNumber, PhoneOtpRejected, PhoneOtpUnavailable } from "./models";
import { PhonePersistence, type PhoneMutation } from "./PhonePersistence";

/** Signup policy runs before the code is verified, so a registration hook's policy
 * denial must read like an unknown number: the request sends no code and
 * completion rejects the code. Hook unavailability stays unavailable. */
export const phoneSignUpFailure = (
  error: PhoneOtpRejected | PhoneOtpUnavailable | HookDenied,
): PhoneOtpRejected | PhoneOtpUnavailable => {
  if (error._tag !== "HookDenied") return error;

  return error.reason === "policy" ? PhoneOtpRejected.make({}) : PhoneOtpUnavailable.make({});
};

export const phoneSignUpAllowed = Effect.fnUntraced(function* (
  moduleId: string,
  phoneNumber: PhoneNumber,
) {
  const snapshot = yield* lifecycleSnapshotEffect({
    action: "registration",
    operation: `${moduleId}/register`,
    method: "phone-otp",
    identifiers: [LoginIdentifier.make({ namespace: "phone", value: phoneNumber })],
  }).pipe(Effect.orDie);

  return yield* (yield* LifecycleHooks).before(snapshot).pipe(
    Effect.as(true),
    Effect.catchCause((cause) =>
      cause.reasons.length > 0 &&
      cause.reasons.every(
        (reason) => Cause.isFailReason(reason) && reason.error.reason === "policy",
      )
        ? Effect.succeed(false)
        : Effect.failCause(Cause.map(cause, () => PhoneOtpUnavailable.make({}))),
    ),
  );
});

/** Keep account/credential changes, proof consumption and their event under one owner. */
export const commitPhoneMutation = Effect.fnUntraced(function* (
  input: PhoneMutation,
  now: DateTime.Utc,
) {
  const hooks = yield* LifecycleHooks;

  const snapshot = yield* lifecycleSnapshotEffect({
    action: input.action === "register" ? "registration" : "identifier-change",
    operation: `${input.moduleId}/${input.action}`,
    method: "phone-otp",
    identifiers: [input.redemption.input.binding.identifier],
    ...(input.target.revision === null ? {} : { subjectId: input.target.revision.subjectId }),
  }).pipe(Effect.orDie);

  yield* hooks.before(snapshot);

  const decision = yield* (yield* PhonePersistence)
    .mutate(input, (decision, journal) => {
      if (decision._tag === "Accepted")
        journal.stage(
          lifecycleEvent({
            id: LifecycleEventId.make(`phone/${input.moduleId}/${input.commandId}`),
            occurredAtMillis: now.epochMilliseconds,
            snapshot: { ...snapshot, subjectId: decision.credential.revision.subjectId },
          }),
        );

      return journal.prepare(decision);
    })
    .pipe(
      Effect.flatMap((receipt) => receipt.read),
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))),
    );

  if (decision._tag !== "Accepted") return yield* PhoneOtpRejected.make({});

  return decision.credential;
});
