import {
  PhoneCommandId,
  PhoneLifecycleAction,
  PhoneCustody,
  PhoneCredentialSnapshot,
  type PhoneAdmission,
  type PhoneAdmissionPolicy,
  type PhoneSignInTargets,
} from "@yielded/auth/PhoneOtp";
import type { AuthenticationRevision } from "@yielded/auth/Sessions";
import { Effect, Option, Schema } from "effect";

import { digest } from "./crypto";

export const PhoneAdmissionReceipt = Schema.Struct({
  fingerprint: Schema.NonEmptyString,
  network: Schema.NonEmptyString,
  accepted: Schema.Boolean,
  expiresAtMillis: Schema.Natural,
});

export const PhoneAdmissionCounter = Schema.Struct({
  window: Schema.Natural,
  count: Schema.Natural,
});

export const PhoneCommandRecord = Schema.Struct({
  commandId: PhoneCommandId,
  action: PhoneLifecycleAction,
});

export const PhoneStoredState = Schema.fromJsonString(
  Schema.Struct({
    moduleId: Schema.NonEmptyString,
    record: Schema.Union([
      PhoneCustody,
      PhoneAdmissionReceipt,
      PhoneAdmissionCounter,
      PhoneCommandRecord,
    ]),
  }),
);

const stringTuple = Schema.fromJsonString(Schema.Array(Schema.String));

export const phoneStateScope = (moduleId: string, kind: string, key: string) =>
  Schema.encodeEffect(stringTuple)(["effect-auth/phone/v1", moduleId, kind, key]).pipe(
    Effect.flatMap(digest),
  );

export type PhoneAdmissionInput = Parameters<PhoneAdmission["Service"]["admit"]>[0];

export const validPhoneAdmissionInput = (input: PhoneAdmissionInput) =>
  Number.isSafeInteger(input.replayLifetimeMillis) &&
  input.replayLifetimeMillis >= 0 &&
  input.networkKey.length > 0 &&
  input.networkKey.length <= 1024 &&
  input.requestId.length > 0 &&
  input.requestId.length <= 256;

export const phoneAdmissionReplay = (
  saved: typeof PhoneAdmissionReceipt.Type,
  input: PhoneAdmissionInput,
  network: string,
  now: number,
) =>
  saved.fingerprint === input.fingerprint &&
  saved.network === network &&
  saved.accepted &&
  saved.expiresAtMillis > now;

export const phoneAdmissionDecision = (
  now: number,
  policy: PhoneAdmissionPolicy,
  counters: ReadonlyArray<{
    readonly previous: typeof PhoneAdmissionCounter.Type | undefined;
    readonly limit: number;
  }>,
) => {
  const window = Math.floor(now / policy.windowMillis);
  const counts = counters.map(({ previous }) => (previous?.window === window ? previous.count : 0));

  return {
    window,
    counts,
    accepted: counts.every((count, index) => count < counters[index]!.limit),
  };
};

export const phoneAdmissionExpiry = (
  record: (typeof PhoneStoredState.Type)["record"],
  policy: PhoneAdmissionPolicy,
) =>
  Schema.is(PhoneAdmissionReceipt)(record)
    ? record.expiresAtMillis
    : Schema.is(PhoneAdmissionCounter)(record)
      ? (record.window + 1) * policy.windowMillis
      : undefined;

export const phoneSignInSnapshot = (
  input: Parameters<PhoneSignInTargets["Service"]["lookup"]>[0],
  custody: PhoneCustody | null,
  revision: AuthenticationRevision | null,
  identifierCurrent: boolean,
) => {
  if (
    custody === null ||
    custody.state !== "verified" ||
    custody.verifiedAtMillis === null ||
    revision === null ||
    !revision.credentials.some((credential) => credential.credentialId === custody.credentialId) ||
    !identifierCurrent
  )
    return Effect.succeed(Option.none<PhoneCredentialSnapshot>());

  return Schema.decodeEffect(PhoneCredentialSnapshot)({
    moduleId: input.moduleId,
    phoneNumber: input.phoneNumber,
    custodyRevision: custody.custodyRevision,
    verifiedAtMillis: custody.verifiedAtMillis,
    credentialId: custody.credentialId,
    credentialRevision: custody.credentialRevision,
    revision,
  }).pipe(Effect.map(Option.some));
};
