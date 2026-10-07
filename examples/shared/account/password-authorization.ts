import { Operations, Password, Sessions } from "@yielded/auth";
import { DateTime, Effect } from "effect";

import type { AppAuth } from "./auth";
import { requirement } from "./auth";

/** Bind recent passkey assurance to the private provenance of this exact session. */
export const authorizePasswordSession = Effect.fn("Customers.authorizePasswordSession")(function* (
  invocation: Operations.AuthInvocation,
  challenge: Password.PasswordActionChallenge,
  source: Effect.Success<ReturnType<typeof AppAuth.sessions.inspectInvocation>>,
) {
  if (invocation._tag !== "Authenticated") return yield* Password.PasswordActionRequired.make({});

  const now = DateTime.toEpochMillis(yield* DateTime.now);
  const age = now - DateTime.toEpochMillis(invocation.assurance.authenticatedAt);

  if (age < 0 || age >= requirement.maximumAgeMillis)
    return yield* Password.PasswordActionRequired.make({});
  yield* Operations.requireAssurance(invocation, {
    maximumAgeMillis: requirement.maximumAgeMillis,
    factors: ["possession"],
    userVerified: true,
    phishingResistant: true,
  });

  const original = source.provenance.evidence;

  if (
    source.session.sessionId !== invocation.sessionId ||
    source.session.subjectId !== invocation.subjectId ||
    original.revision.subjectId !== challenge.revision.subjectId ||
    original.revision.securityRevision !== challenge.revision.securityRevision
  )
    return yield* Password.PasswordActionRequired.make({});

  const captured = [...challenge.revision.credentials, ...original.revision.credentials];

  const capture = yield* (yield* Sessions.AuthenticationAuthority).capture(
    challenge.revision.subjectId,
    [...new Set(captured.map((item) => item.credentialId))],
  );

  const revision = capture.revision;

  if (
    revision.securityRevision !== challenge.revision.securityRevision ||
    captured.some(
      (item) =>
        !revision.credentials.some(
          (current) =>
            current.credentialId === item.credentialId && current.revision === item.revision,
        ),
    )
  )
    return yield* Password.PasswordActionRequired.make({});

  return {
    evidence: {
      ...original,
      revision,
      flowId: Sessions.AuthenticationFlowId.make(challenge.commandId),
      bindingDigest: challenge.bindingDigest,
    },
    requirement,
  };
});
