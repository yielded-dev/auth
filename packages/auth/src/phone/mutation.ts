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
import { reportAuthFailure } from "../internal/diagnostics";
import { phoneFailure } from "./failure";
import { type PhoneNumber, PhoneOtpRejected, type PhoneOtpUnavailable } from "./models";
import { PhonePersistence, type PhoneMutation } from "./PhonePersistence";

type PhoneSignUpFailure = PhoneOtpRejected | PhoneOtpUnavailable | HookDenied;

const reportUnavailableHook = (cause: Cause.Cause<PhoneSignUpFailure>) =>
  reportAuthFailure(
    "before-hook",
    Cause.fromReasons(
      cause.reasons.filter(
        (reason) =>
          Cause.isFailReason(reason) &&
          reason.error._tag === "HookDenied" &&
          reason.error.reason === "unavailable",
      ),
    ),
  );

/** Signup consults the registration hook only for unused numbers and before the
 * code is verified, so the hook's answer must not shape the response. Signup fails
 * closed: when the hook denies or is unavailable, the request sends no code and
 * completion rejects without redeeming the code. Nothing is committed or consumed,
 * and an unavailable hook is reported for operators instead of to the caller. */
export const phoneSignUpFailure = (cause: Cause.Cause<PhoneSignUpFailure>) =>
  reportUnavailableHook(cause).pipe(
    Effect.andThen(
      cause.reasons.length > 0 &&
        cause.reasons.every(
          (reason) => Cause.isFailReason(reason) && reason.error._tag === "HookDenied",
        )
        ? Effect.fail(PhoneOtpRejected.make({}))
        : Effect.failCause(
            Cause.map(cause, (error) =>
              error._tag === "HookDenied" ? PhoneOtpRejected.make({}) : error,
            ),
          ),
    ),
  );

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
      cause.reasons.length > 0 && cause.reasons.every(Cause.isFailReason)
        ? reportUnavailableHook(cause).pipe(Effect.as(false))
        : Effect.failCause(
            Cause.fromReasons<never>(
              cause.reasons.filter(
                (reason) => Cause.isDieReason(reason) || Cause.isInterruptReason(reason),
              ),
            ),
          ),
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
