import { IdentityConflict, LoginIdentifier } from "@yielded/auth/Identity";
import type { AuthenticationAssurance } from "@yielded/auth/Operations";
import { SubjectId } from "@yielded/auth/Schema";
import * as Sessions from "@yielded/auth/Sessions";
import { DateTime, Effect, Schema } from "effect";

import { PersistenceUnavailable, Transaction } from "./documents";

/** Application-owned authority records. Provisioning and claims stay with the application.
 * Change securityRevision in the same transaction as status, policy or identifier changes.
 */
export const Subject = Schema.Struct({
  subjectId: SubjectId,
  active: Schema.Boolean,
  securityRevision: Sessions.SecurityRevision,
  requirement: Sessions.AuthenticationRequirement,
  actionRequirement: Schema.optionalKey(Sessions.AuthenticationRequirement),
});

export type Subject = typeof Subject.Type;

export const AuthorityCredential = Schema.Struct({
  subjectId: SubjectId,
  credentialId: Schema.NonEmptyString,
  revision: Sessions.SecurityRevision,
  active: Schema.Boolean,
});

export type AuthorityCredential = typeof AuthorityCredential.Type;

export const Identifier = Schema.Struct({
  identifier: LoginIdentifier,
  subjectId: SubjectId,
  bindingRevision: Sessions.SecurityRevision,
  verifiedAtMillis: Schema.optionalKey(Schema.Int),
  credentialId: Schema.optionalKey(Schema.NonEmptyString),
});

export type Identifier = typeof Identifier.Type;

/** Tuple encoding keeps user-controlled namespaces and identifiers collision-free. */
export const tupleKey = (...parts: ReadonlyArray<string>): string => JSON.stringify(parts);
export const subjectKey = (subjectId: string): string => subjectId;
export const credentialKey = (credentialId: string): string => credentialId;

export const identifierKey = (identifier: LoginIdentifier): string =>
  tupleKey(identifier.namespace, identifier.value);

export const identityPartitions = {
  subjects: "identity/subjects",
  identifiers: "identity/identifiers",
  subjectIdentifiers: (subjectId: string) => tupleKey("identity/subject-identifiers", subjectId),
  credentials: (subjectId: string) => tupleKey("identity/credentials", subjectId),
};

/** Preserve global uniqueness and the subject's bounded identifier index together.
 * The caller owns policy and bumps securityRevision for semantic binding changes.
 */
export const bindIdentifier = Effect.fnUntraced(function* (value: Identifier) {
  const tx = yield* Transaction;
  const key = identifierKey(value.identifier);
  const previous = yield* tx.get(Identifier, identityPartitions.identifiers, key);

  if (previous !== undefined) {
    if (identifierKey(previous.identifier) !== key) return yield* PersistenceUnavailable.make({});
    if (previous.subjectId !== value.subjectId) return yield* IdentityConflict.make({});
  }
  yield* tx.put(Identifier, identityPartitions.identifiers, key, value);
  yield* tx.put(Identifier, identityPartitions.subjectIdentifiers(value.subjectId), key, value);
});

/** Helpers join the caller's Transaction; they never start a nested document commit. */
export const activeSubject = Effect.fnUntraced(function* (subjectId: SubjectId) {
  const tx = yield* Transaction;
  const subject = yield* tx.get(Subject, identityPartitions.subjects, subjectKey(subjectId));

  if (subject === undefined || !subject.active || subject.subjectId !== subjectId)
    return yield* Sessions.StaleAuthentication.make({});

  return subject;
});

export const currentRevision = Effect.fnUntraced(function* (
  subjectId: SubjectId,
  credentialIds: ReadonlyArray<string>,
) {
  if (credentialIds.length > 64 || new Set(credentialIds).size !== credentialIds.length)
    return yield* Sessions.StaleAuthentication.make({});
  const tx = yield* Transaction;
  const subject = yield* activeSubject(subjectId);
  const credentials: Array<Sessions.CredentialRevision> = [];

  for (const credentialId of [...credentialIds].sort()) {
    const credential = yield* tx.get(
      AuthorityCredential,
      identityPartitions.credentials(subjectId),
      credentialKey(credentialId),
    );

    if (
      credential === undefined ||
      !credential.active ||
      credential.subjectId !== subjectId ||
      credential.credentialId !== credentialId
    )
      return yield* Sessions.StaleAuthentication.make({});
    credentials.push({ credentialId, revision: credential.revision });
  }

  return {
    subjectId,
    securityRevision: subject.securityRevision,
    credentials,
  } satisfies Sessions.AuthenticationRevision;
});

export const revisionCurrent = Effect.fnUntraced(
  function* (expected: Sessions.AuthenticationRevision) {
    const snapshot = yield* Schema.decodeEffect(Sessions.AuthenticationRevision)(expected).pipe(
      Effect.mapError(() => Sessions.StaleAuthentication.make({})),
    );

    const current = yield* currentRevision(
      snapshot.subjectId,
      snapshot.credentials.map((credential) => credential.credentialId),
    );

    return (
      current.securityRevision === snapshot.securityRevision &&
      snapshot.credentials.every((credential) =>
        current.credentials.some(
          (actual) =>
            actual.credentialId === credential.credentialId &&
            actual.revision === credential.revision,
        ),
      )
    );
  },
  Effect.catchTag("StaleAuthentication", () => Effect.succeed(false)),
);

/** Revalidate original authority and assess at the server-sampled Clock. Register
 * the earliest contributing proof deadline so a delayed commit cannot change the assessment.
 * An unsatisfied assessment is valid for pending authentication, never a session.
 */
export const evidenceCurrent = Effect.fnUntraced(function* (
  evidence: Sessions.AuthenticationEvidence,
  configured?: Sessions.AuthenticationRequirement,
): Effect.fn.Return<
  {
    readonly subject: Subject;
    readonly requirement: Sessions.AuthenticationRequirement;
    readonly assessment: {
      readonly satisfied: boolean;
      readonly assurance: AuthenticationAssurance;
    };
  },
  Sessions.StaleAuthentication | PersistenceUnavailable,
  Transaction
> {
  if (!(yield* revisionCurrent(evidence.revision)))
    return yield* Sessions.StaleAuthentication.make({});
  const tx = yield* Transaction;
  const subject = yield* activeSubject(evidence.revision.subjectId);
  const requirement = configured ?? subject.requirement;

  const assessment = yield* Sessions.assessAuthentication(evidence, requirement).pipe(
    Effect.catchTag("SessionConfigurationError", () => PersistenceUnavailable.make({})),
  );

  const deadlines = evidence.proofs
    .map((proof) => DateTime.toEpochMillis(proof.verifiedAt) + requirement.maximumAgeMillis)
    .filter((deadline) => deadline > tx.now);

  yield* tx.before(Math.min(...deadlines));

  return { subject, requirement, assessment };
});

/** Immediate invalidation without an unbounded scan or deletion of sessions. */
export const invalidateSubject = Effect.fnUntraced(function* (
  subjectId: SubjectId,
  expectedRevision?: Sessions.SecurityRevision,
) {
  const tx = yield* Transaction;
  const subject = yield* activeSubject(subjectId);

  if (expectedRevision !== undefined && subject.securityRevision !== expectedRevision)
    return yield* Sessions.StaleAuthentication.make({});
  const next = { ...subject, securityRevision: Sessions.SecurityRevision.make(yield* tx.id) };

  if (next.securityRevision === subject.securityRevision)
    return yield* PersistenceUnavailable.make({});

  yield* tx.put(Subject, identityPartitions.subjects, subjectKey(subjectId), next);

  return next;
});
