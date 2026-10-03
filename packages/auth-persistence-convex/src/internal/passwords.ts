import type { PreparedCommit } from "@yielded/auth/Hooks";
import type { LoginIdentifier } from "@yielded/auth/Identity";
import { LoginIdentifier as IdentifierSchema } from "@yielded/auth/Identity";
import * as Password from "@yielded/auth/Password";
import { SubjectId } from "@yielded/auth/Schema";
import * as Sessions from "@yielded/auth/Sessions";
import { Context, Effect, Layer, Option, Redacted, Schema } from "effect";

import type { PersistenceUnavailable } from "./documents";
import { DocumentStore, Transaction } from "./documents";
import {
  Subject,
  Identifier,
  AuthorityCredential,
  identityPartitions,
  identifierKey,
  tupleKey,
  revisionCurrent,
  currentRevision,
  evidenceCurrent,
  invalidateSubject,
  bindIdentifier,
} from "./identity";
import { completionCurrent, consumeCompletion } from "./proofs";

const Credential = Schema.Struct({
  subjectId: SubjectId,
  credentialId: Schema.NonEmptyString,
  revision: Sessions.SecurityRevision,
  verifierVersion: Sessions.SecurityRevision,
  replacement: Password.PasswordReplacement,
  identifier: IdentifierSchema,
});

const Attempt = Schema.Struct({
  captured: Schema.optionalKey(Password.PasswordCredentialSnapshot),
  pending: Schema.Boolean,
  deadline: Schema.Int,
  retentionUntil: Schema.Int,
  scopes: Schema.Array(Schema.String),
});

const Charge = Schema.Struct({
  id: Schema.String,
  at: Schema.Int,
  pendingUntil: Schema.Int,
  retentionUntil: Schema.Int,
});

const Charges = Schema.Array(Charge).check(Schema.isMaxLength(4096));
const Expiry = Schema.Struct({ key: Schema.String, expiresAt: Schema.Int });
const Command = Schema.Struct({ subjectId: SubjectId, action: Password.PasswordAction });

const Registration = Schema.Struct({
  identifier: IdentifierSchema,
  subjectId: SubjectId,
  replacement: Password.PasswordReplacement,
});

const credentials = (moduleId: string) => tupleKey("password/credentials", moduleId);
const attempts = (moduleId: string) => tupleKey("password/attempts", moduleId);
const expiry = (moduleId: string) => tupleKey("password/expiry", moduleId);
const charges = (moduleId: string) => tupleKey("password/charges", moduleId);
const commands = (moduleId: string) => tupleKey("password/commands", moduleId);
const expiryKey = (time: number, id: string) => `${String(time).padStart(16, "0")}/${id}`;

const encodeSnapshot = Schema.encodeSync(
  Schema.fromJsonString(Password.PasswordCredentialSnapshot),
);

const snapshot = Effect.fnUntraced(
  function* (moduleId: string, subjectId: SubjectId, selected?: LoginIdentifier) {
    const tx = yield* Transaction;
    const subject = yield* tx.get(Subject, identityPartitions.subjects, subjectId);
    const credential = yield* tx.get(Credential, credentials(moduleId), subjectId);

    if (
      subject === undefined ||
      !subject.active ||
      subject.subjectId !== subjectId ||
      credential === undefined ||
      credential.subjectId !== subjectId
    )
      return undefined;
    const identifier = selected ?? credential.identifier;

    const binding = yield* tx.get(
      Identifier,
      identityPartitions.identifiers,
      identifierKey(identifier),
    );

    if (
      binding === undefined ||
      binding.subjectId !== subjectId ||
      identifierKey(binding.identifier) !== identifierKey(identifier)
    )
      return undefined;
    const revision = yield* currentRevision(subjectId, [credential.credentialId]);

    if (revision.credentials[0]?.revision !== credential.revision) return undefined;

    return Password.PasswordCredentialSnapshot.make({
      moduleId,
      revision,
      credentialId: credential.credentialId,
      credentialRevision: credential.revision,
      verifierVersion: credential.verifierVersion,
      verifier: credential.replacement.verifier,
      normalization: credential.replacement.normalization,
      identifier,
      identifierBindingRevision: binding.bindingRevision,
      ...(binding.verifiedAtMillis === undefined
        ? {}
        : { identifierVerifiedAtMillis: binding.verifiedAtMillis }),
    });
  },
  Effect.catchTag("StaleAuthentication", () => Effect.succeed(undefined)),
);

const writeCredential = Effect.fnUntraced(function* (
  moduleId: string,
  subjectId: SubjectId,
  identifier: LoginIdentifier,
  replacement: Password.PasswordReplacement,
  previous?: typeof Credential.Type,
) {
  const tx = yield* Transaction;

  const value = {
    subjectId,
    identifier,
    replacement,
    credentialId: previous?.credentialId ?? (yield* tx.id),
    revision: Sessions.SecurityRevision.make(yield* tx.id),
    verifierVersion: Sessions.SecurityRevision.make(yield* tx.id),
  };

  yield* tx.put(Credential, credentials(moduleId), subjectId, value);
  yield* tx.put(
    AuthorityCredential,
    identityPartitions.credentials(subjectId),
    value.credentialId,
    {
      subjectId,
      credentialId: value.credentialId,
      revision: value.revision,
      active: true,
    },
  );
});

/** Compare current action policy independently of the caller's captured authorization. */
const mutationCurrent = Effect.fnUntraced(
  function* (input: Password.PasswordMutationInput, action: Password.PasswordAction) {
    const tx = yield* Transaction;
    const { authorization: auth } = input;

    const subject = yield* tx.get(
      Subject,
      identityPartitions.subjects,
      input.expectedRevision.subjectId,
    );

    if (
      subject === undefined ||
      !subject.active ||
      !(yield* revisionCurrent(input.expectedRevision)) ||
      !(yield* revisionCurrent(auth.challenge.revision)) ||
      auth.challenge.moduleId !== input.moduleId ||
      auth.challenge.action !== action ||
      auth.challenge.commandId !== input.commandId ||
      auth.challenge.revision.subjectId !== input.expectedRevision.subjectId ||
      auth.evidence.revision.subjectId !== input.expectedRevision.subjectId ||
      String(auth.evidence.flowId) !== String(input.commandId) ||
      auth.evidence.bindingDigest !== auth.challenge.bindingDigest ||
      input.invalidation.oldAuthenticationEvidence !== "rejected" ||
      (yield* tx.get(Command, commands(input.moduleId), input.commandId)) !== undefined
    )
      return false;
    const captured = yield* evidenceCurrent(auth.evidence, auth.requirement);

    const current = yield* evidenceCurrent(
      auth.evidence,
      subject.actionRequirement ?? subject.requirement,
    );

    if (!captured.assessment.satisfied || !current.assessment.satisfied) return false;

    const actual = yield* snapshot(
      input.moduleId,
      input.expectedRevision.subjectId,
      input.credential?.identifier,
    );

    if (action === "add-password")
      return (
        (yield* tx.get(
          Credential,
          credentials(input.moduleId),
          input.expectedRevision.subjectId,
        )) === undefined &&
        input.credential === undefined &&
        auth.challenge.targetCredentialId === undefined
      );

    return (
      actual !== undefined &&
      input.credential !== undefined &&
      actual.credentialId === input.credential.credentialId &&
      actual.credentialRevision === input.credential.credentialRevision &&
      actual.verifierVersion === input.credential.verifierVersion &&
      Redacted.value(actual.verifier) === Redacted.value(input.credential.verifier) &&
      actual.identifierBindingRevision === input.credential.identifierBindingRevision &&
      auth.challenge.targetCredentialId === actual.credentialId
    );
  },
  Effect.catchTag("StaleAuthentication", () => Effect.succeed(false)),
);

const sameRevision = (a: Sessions.AuthenticationRevision, b: Sessions.AuthenticationRevision) => {
  const credentials = new Map(a.credentials.map((item) => [item.credentialId, item.revision]));

  return (
    a.subjectId === b.subjectId &&
    a.securityRevision === b.securityRevision &&
    credentials.size === a.credentials.length &&
    new Set(b.credentials.map((item) => item.credentialId)).size === b.credentials.length &&
    a.credentials.length === b.credentials.length &&
    b.credentials.every((item) => credentials.get(item.credentialId) === item.revision)
  );
};

export const PasswordPersistence = {
  layer: Layer.effect(
    Password.PasswordPersistence,
    Effect.gen(function* () {
      const store = yield* DocumentStore;

      const run = <A, E, R>(body: Effect.Effect<A, E, R>) =>
        store.transaction(body).pipe(Effect.mapError(() => Password.PasswordUnavailable.make({})));

      const mutate = <A>(
        input: Password.PasswordMutationInput,
        action: Password.PasswordAction,
        prepare: Password.PreparePasswordCommit<Password.PasswordMutationDecision, A>,
      ) =>
        run(
          Effect.gen(function* () {
            const tx = yield* Transaction;

            if (!(yield* mutationCurrent(input, action))) return prepare("rejected", tx.journal);

            const previous = yield* tx.get(
              Credential,
              credentials(input.moduleId),
              input.expectedRevision.subjectId,
            );

            const identifier =
              input.credential?.identifier ?? input.authorization.evidence.revision.subjectId;

            // Adding a password uses an application-owned identifier already bound to this subject.
            const selected =
              typeof identifier === "string"
                ? (yield* tx.scan(
                    Identifier,
                    identityPartitions.subjectIdentifiers(identifier),
                  )).find((row) => row.value.subjectId === identifier)?.value.identifier
                : identifier;

            if (selected === undefined) return prepare("rejected", tx.journal);
            yield* writeCredential(
              input.moduleId,
              input.expectedRevision.subjectId,
              selected,
              input.replacement,
              previous,
            );
            yield* invalidateSubject(
              input.expectedRevision.subjectId,
              input.expectedRevision.securityRevision,
            );
            yield* tx.put(Command, commands(input.moduleId), input.commandId, {
              subjectId: input.expectedRevision.subjectId,
              action,
            });

            return prepare("changed", tx.journal);
          }),
        );

      return Password.PasswordPersistence.of({
        admitAttempt: (input, prepare) =>
          run(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              const policy = yield* Schema.decodeEffect(Password.PasswordAttemptPolicy)(
                input.policy,
              );

              const binding = yield* tx.get(
                Identifier,
                identityPartitions.identifiers,
                identifierKey(input.identifier),
              );

              const known =
                binding === undefined
                  ? undefined
                  : yield* snapshot(input.moduleId, binding.subjectId, input.identifier);

              const captured =
                known !== undefined &&
                (input.subjectId === undefined || input.subjectId === known.revision.subjectId)
                  ? known
                  : undefined;

              const buckets = [
                { key: tupleKey(input.action, "action"), ...policy.action },
                {
                  key: tupleKey(input.action, "identifier", identifierKey(input.identifier)),
                  ...policy.identifier,
                },
                ...(binding === undefined
                  ? []
                  : [
                      {
                        key: tupleKey(input.action, "subject", binding.subjectId),
                        ...policy.subject,
                      },
                    ]),
              ];

              const observed = yield* Effect.forEach(buckets, (bucket) =>
                Effect.gen(function* () {
                  const all = yield* tx.get(Charges, charges(input.moduleId), bucket.key);
                  const retained = (all ?? []).filter((entry) => entry.retentionUntil >= tx.now);

                  return {
                    ...bucket,
                    retained,
                    open:
                      retained.filter((entry) => entry.at >= tx.now - bucket.windowMillis).length <
                      bucket.limit,
                    pending:
                      retained.filter((entry) => entry.pendingUntil > tx.now).length <
                      policy.maximumPending,
                  };
                }),
              );

              const admitted = observed.every((bucket) => bucket.open && bucket.pending);
              const attemptId = Password.PasswordAttemptId.make(yield* tx.id);
              const deadline = tx.now + policy.attemptLifetimeMillis;

              const retentionUntil =
                tx.now +
                Math.max(
                  policy.attemptLifetimeMillis,
                  ...buckets.map((bucket) => bucket.windowMillis),
                );

              for (const bucket of observed)
                if (bucket.open)
                  yield* tx.put(Charges, charges(input.moduleId), bucket.key, [
                    ...bucket.retained,
                    {
                      id: attemptId,
                      at: tx.now,
                      pendingUntil: admitted ? deadline : 0,
                      retentionUntil,
                    },
                  ]);
              if (!admitted) return prepare({ _tag: "Denied" }, tx.journal);
              yield* tx.before(deadline);
              yield* tx.put(Attempt, attempts(input.moduleId), attemptId, {
                pending: true,
                deadline,
                retentionUntil,
                scopes: buckets.map((bucket) => bucket.key),
                ...(captured === undefined ? {} : { captured }),
              });
              yield* tx.put(Expiry, expiry(input.moduleId), expiryKey(retentionUntil, attemptId), {
                key: attemptId,
                expiresAt: retentionUntil,
              });

              return prepare(
                {
                  _tag: "Admitted",
                  attemptId,
                  ...(captured === undefined ? {} : { credential: captured }),
                },
                tx.journal,
              );
            }),
          ),
        settleAttempt: (input, prepare) =>
          run(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const attempt = yield* tx.get(Attempt, attempts(input.moduleId), input.attemptId);

              if (attempt === undefined || !attempt.pending) return prepare("rejected", tx.journal);
              const captured = input.captured;

              const current =
                captured === undefined
                  ? undefined
                  : yield* snapshot(
                      input.moduleId,
                      captured.revision.subjectId,
                      captured.identifier,
                    );

              const verified =
                input.outcome === "verified" &&
                tx.now < attempt.deadline &&
                captured !== undefined &&
                attempt.captured !== undefined &&
                current !== undefined &&
                encodeSnapshot(captured) === encodeSnapshot(attempt.captured) &&
                (yield* revisionCurrent(captured.revision)) &&
                current.credentialId === captured.credentialId &&
                current.credentialRevision === captured.credentialRevision &&
                current.identifierBindingRevision === captured.identifierBindingRevision;

              yield* tx.put(Attempt, attempts(input.moduleId), input.attemptId, {
                ...attempt,
                pending: false,
              });
              for (const key of attempt.scopes) {
                const existing = yield* tx.get(Charges, charges(input.moduleId), key);

                if (existing !== undefined)
                  yield* tx.put(
                    Charges,
                    charges(input.moduleId),
                    key,
                    existing.map((entry) =>
                      entry.id === input.attemptId ? { ...entry, pendingUntil: 0 } : entry,
                    ),
                  );
              }
              if (verified) {
                yield* tx.before(attempt.deadline);
                const rehash = input.rehash;

                if (rehash !== undefined && current !== undefined) {
                  const previous = yield* tx.get(
                    Credential,
                    credentials(input.moduleId),
                    current.revision.subjectId,
                  );

                  if (
                    previous !== undefined &&
                    previous.verifierVersion === rehash.expectedVersion &&
                    Redacted.value(previous.replacement.verifier) ===
                      Redacted.value(rehash.expectedVerifier)
                  )
                    yield* tx.put(Credential, credentials(input.moduleId), previous.subjectId, {
                      ...previous,
                      verifierVersion: Sessions.SecurityRevision.make(yield* tx.id),
                      replacement: { ...previous.replacement, verifier: rehash.nextVerifier },
                    });
                }
              }

              return prepare(verified ? "verified" : "rejected", tx.journal);
            }),
          ),
        readForSubject: (input) =>
          run(snapshot(input.moduleId, input.subjectId).pipe(Effect.map(Option.fromNullishOr))),
        recoveryTarget: (input) =>
          run(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              const binding = yield* tx.get(
                Identifier,
                identityPartitions.identifiers,
                identifierKey(input.identifier),
              );

              if (binding?.verifiedAtMillis === undefined) return Option.none();

              return Option.fromNullishOr(
                yield* snapshot(input.moduleId, binding.subjectId, input.identifier),
              );
            }),
          ),
        addIfAbsent: (input, prepare) => mutate(input, "add-password", prepare),
        replaceIfCurrent: (input, prepare) => mutate(input, "change-password", prepare),
        checkReset: (input) => run(completionCurrent(input)),
        resetWithProof: (input, prepare) =>
          run(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const proof = input.completion.input;

              if (
                proof.binding._tag !== "Subject" ||
                input.credential === undefined ||
                proof.moduleId !== `${input.moduleId}/reset` ||
                identifierKey(proof.binding.identifier) !==
                  identifierKey(input.credential.identifier) ||
                !sameRevision(proof.binding.revision, input.expectedRevision) ||
                proof.purpose !== "password-reset" ||
                !(yield* completionCurrent(proof)) ||
                !(yield* mutationCurrent(input, "reset-password"))
              )
                return prepare("rejected", tx.journal);

              const previous = yield* tx.get(
                Credential,
                credentials(input.moduleId),
                input.expectedRevision.subjectId,
              );

              if (previous === undefined) return prepare("rejected", tx.journal);
              if (!(yield* consumeCompletion(proof))) return prepare("rejected", tx.journal);
              yield* writeCredential(
                input.moduleId,
                previous.subjectId,
                previous.identifier,
                input.replacement,
                previous,
              );
              yield* invalidateSubject(previous.subjectId, input.expectedRevision.securityRevision);
              yield* tx.put(Command, commands(input.moduleId), input.commandId, {
                subjectId: previous.subjectId,
                action: "reset-password",
              });
              input.completion.prepare("completed", tx.journal, () => undefined);

              return prepare("changed", tx.journal);
            }),
          ),
        cleanupAttempts: (input, prepare) =>
          run(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              const limit = yield* Schema.decodeUnknownEffect(
                Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 50 })),
              )(input.limit);

              const rows = yield* tx.scan(Expiry, expiry(input.moduleId), { limit: limit + 1 });
              const expired = rows.filter((row) => row.value.expiresAt <= tx.now);

              for (const row of expired.slice(0, limit)) {
                yield* tx.remove(attempts(input.moduleId), row.value.key);
                yield* tx.remove(expiry(input.moduleId), row.key);
              }

              return prepare(
                { removed: Math.min(expired.length, limit), hasMore: expired.length > limit },
                tx.journal,
              );
            }),
          ),
      });
    }),
  ),
};

export interface RegistrationService<Data> {
  readonly register: <A>(
    input: {
      readonly moduleId: string;
      readonly requestId: string;
      readonly identifier: LoginIdentifier;
      readonly registration: Data;
      readonly replacement: Password.PasswordReplacement;
    },
    prepare: Password.PreparePasswordCommit<Password.PasswordRegistrationDecision, A>,
  ) => Effect.Effect<PreparedCommit<A>, Password.PasswordUnavailable>;
}

export interface PasswordProvisioning<Id, Data> {
  readonly registrationAuthority: Id;
  readonly registrationData: Data;
}

export interface ProvisioningService<Data> {
  readonly create: (input: {
    readonly identifier: LoginIdentifier;
    readonly registration: Data;
  }) => Effect.Effect<
    SubjectId,
    Password.PasswordUnavailable | PersistenceUnavailable,
    Transaction
  >;
}

/** Application provisioning must stage its subject and account through Transaction; never call remote mutations. */
export const makePasswordRegistration = <Id, Data>(
  authority: Context.Key<Id, RegistrationService<Data>>,
  moduleId: string,
): {
  readonly Provisioning: Context.Service<PasswordProvisioning<Id, Data>, ProvisioningService<Data>>;
  readonly layer: Layer.Layer<Id, never, DocumentStore | PasswordProvisioning<Id, Data>>;
} => {
  const Provisioning = Context.Service<PasswordProvisioning<Id, Data>, ProvisioningService<Data>>(
    `effect-auth/convex/${moduleId}/Provisioning`,
  );

  const layer = Layer.effect(
    authority,
    Effect.gen(function* () {
      const store = yield* DocumentStore;
      const provisioning = yield* Provisioning;

      return {
        register: <A>(
          input: Parameters<RegistrationService<Data>["register"]>[0],
          prepare: Password.PreparePasswordCommit<Password.PasswordRegistrationDecision, A>,
        ) =>
          store
            .transaction(
              Effect.gen(function* () {
                const tx = yield* Transaction;
                const partition = tupleKey("password/registrations", moduleId);

                if (input.moduleId !== moduleId)
                  return yield* Password.PasswordUnavailable.make({});
                if (
                  (yield* tx.get(Registration, partition, input.requestId)) !== undefined ||
                  (yield* tx.get(
                    Identifier,
                    identityPartitions.identifiers,
                    identifierKey(input.identifier),
                  )) !== undefined
                )
                  return prepare({ _tag: "Suppressed" }, tx.journal);

                const subjectId = yield* provisioning.create({
                  identifier: input.identifier,
                  registration: input.registration,
                });

                const subject = yield* tx.get(Subject, identityPartitions.subjects, subjectId);

                if (
                  subject === undefined ||
                  !subject.active ||
                  subject.subjectId !== subjectId ||
                  (yield* tx.get(Credential, credentials(moduleId), subjectId)) !== undefined
                )
                  return yield* Password.PasswordUnavailable.make({});
                yield* bindIdentifier({
                  identifier: input.identifier,
                  subjectId,
                  bindingRevision: Sessions.SecurityRevision.make(yield* tx.id),
                });
                yield* writeCredential(moduleId, subjectId, input.identifier, input.replacement);
                yield* tx.put(Registration, partition, input.requestId, {
                  identifier: input.identifier,
                  subjectId,
                  replacement: input.replacement,
                });

                return prepare({ _tag: "Created", subjectId }, tx.journal);
              }),
            )
            .pipe(Effect.mapError(() => Password.PasswordUnavailable.make({}))),
      };
    }),
  );

  return { Provisioning, layer };
};
