import { Hooks, Password, Schema as AuthSchema, Sessions } from "@yielded/auth";
import { Context, Effect, Layer, Option, Schema } from "effect";

import {
  claims,
  current,
  customer,
  evidenceDeadline,
  invalidate,
  passwordCredential,
  satisfies,
} from "./accounts";
import { AppAuth } from "./auth";
import { nextId, type State } from "./model";
import { completionCurrent, consumeCompletion } from "./proofs";
import { AccountStore } from "./store";

const moduleId = AppAuth.strategies.password.persistence.moduleId;

const encodeCredential = Schema.encodeSync(
  Schema.fromJsonString(Password.PasswordCredentialSnapshot),
);

const mutationCurrent = Effect.fn("Customers.passwordMutationCurrent")(function* (
  state: Readonly<State>,
  input: Password.PasswordMutationInput,
) {
  const { authorization: auth } = input;
  const account = customer(state, input.expectedRevision.subjectId);
  const password = account === undefined ? undefined : passwordCredential(state, account);

  return (
    input.moduleId === moduleId &&
    account !== undefined &&
    password !== undefined &&
    input.credential !== undefined &&
    password.credentialId === input.credential.credentialId &&
    password.credentialRevision === input.credential.credentialRevision &&
    current(state, input.expectedRevision) &&
    current(state, auth.challenge.revision) &&
    auth.challenge.moduleId === moduleId &&
    auth.challenge.commandId === input.commandId &&
    auth.challenge.revision.subjectId === account.id &&
    auth.challenge.targetCredentialId === password.credentialId &&
    String(auth.evidence.flowId) === String(input.commandId) &&
    auth.evidence.bindingDigest === auth.challenge.bindingDigest &&
    auth.evidence.revision.subjectId === account.id &&
    input.invalidation.existingSessions === "immediate" &&
    (yield* satisfies(state, auth.evidence, auth.requirement))
  );
});

const replace = (state: State, input: Password.PasswordMutationInput) => {
  state.passwords = state.passwords.map((item) =>
    item.credentialId === input.credential?.credentialId
      ? {
          ...item,
          replacement: input.replacement,
          revision: Sessions.SecurityRevision.make(nextId(state, "password-revision")),
          verifierVersion: Sessions.SecurityRevision.make(nextId(state, "verifier")),
        }
      : item,
  );
  invalidate(state, input.expectedRevision.subjectId);
};

export const PasswordsLive = Layer.effectContext(
  Effect.gen(function* () {
    const store = yield* AccountStore;

    const passwords = Password.PasswordPersistence.of({
      findCredential: (input) =>
        Effect.gen(function* () {
          if (yield* Hooks.hasCommitScope) return yield* Password.PasswordUnavailable.make({});
          if (input.moduleId !== moduleId) return yield* Password.PasswordUnavailable.make({});
          const identifier = { ...input.identifier };
          const requestedSubject = input.subjectId;

          return yield* store.read((state) =>
            Effect.gen(function* () {
              const account = state.customers.find(
                (item) =>
                  item.active &&
                  (identifier.namespace === "email"
                    ? item.email === identifier.value
                    : identifier.namespace === "username" && item.username === identifier.value) &&
                  (requestedSubject === undefined || item.id === requestedSubject),
              );

              const candidate =
                account === undefined ? undefined : passwordCredential(state, account);

              return candidate === undefined
                ? Option.none()
                : Option.some(yield* Password.snapshotPasswordCredential(candidate));
            }),
          );
        }).pipe(Effect.catchTag("StoreUnavailable", () => Password.PasswordUnavailable.make({}))),
      rehashIfCurrent: (input) =>
        store
          .transaction((state, journal) =>
            Effect.sync(() => {
              const captured = input.credential;
              const account = customer(state, captured.revision.subjectId);
              const actual = account === undefined ? undefined : passwordCredential(state, account);

              if (
                captured.moduleId === moduleId &&
                actual !== undefined &&
                encodeCredential(actual) === encodeCredential(captured)
              )
                state.passwords = state.passwords.map((item) =>
                  item.credentialId === captured.credentialId
                    ? {
                        ...item,
                        replacement: { ...item.replacement, verifier: input.nextVerifier },
                        verifierVersion: Sessions.SecurityRevision.make(nextId(state, "verifier")),
                      }
                    : item,
                );

              return journal.prepare(undefined);
            }),
          )
          .pipe(
            Effect.flatMap((receipt) => receipt.read),
            Effect.mapError(() => Password.PasswordUnavailable.make({})),
          ),
      readForSubject: (input) =>
        store
          .read((state) =>
            Effect.sync(() => {
              const account =
                input.moduleId === moduleId ? customer(state, input.subjectId) : undefined;

              return Option.fromNullishOr(
                account === undefined ? undefined : passwordCredential(state, account),
              );
            }),
          )
          .pipe(Effect.catchTag("StoreUnavailable", () => Password.PasswordUnavailable.make({}))),
      recoveryTarget: (input) =>
        store
          .read((state) =>
            Effect.sync(() => {
              const account =
                input.moduleId === moduleId && input.identifier.namespace === "email"
                  ? state.customers.find(
                      (item) =>
                        item.active &&
                        item.email === input.identifier.value &&
                        item.verifiedAtMillis !== undefined,
                    )
                  : undefined;

              return Option.fromNullishOr(
                account === undefined ? undefined : passwordCredential(state, account),
              );
            }),
          )
          .pipe(Effect.catchTag("StoreUnavailable", () => Password.PasswordUnavailable.make({}))),
      // Every customer in this application registers a password; adding another is unsupported.
      addIfAbsent: () => Effect.fail(Password.PasswordUnavailable.make({})),
      replaceIfCurrent: (input, prepare) =>
        store
          .transaction((state, journal, now) =>
            Effect.gen(function* () {
              if (
                input.authorization.challenge.action !== "change-password" ||
                !(yield* mutationCurrent(state, input)) ||
                state.mutations.some(
                  (item) => item.moduleId === moduleId && item.commandId === input.commandId,
                )
              )
                return prepare("rejected", journal);
              const receipt = prepare("changed", journal);

              journal.beforeCommit(
                (time) =>
                  time >= now &&
                  time <
                    evidenceDeadline(input.authorization.evidence, input.authorization.requirement),
              );
              replace(state, input);
              state.mutations = [
                ...state.mutations,
                {
                  moduleId,
                  commandId: input.commandId,
                  subjectId: input.expectedRevision.subjectId,
                  kind: "password",
                  retentionUntil: now + 3_600_000,
                },
              ];

              return receipt;
            }),
          )
          .pipe(Effect.mapError(() => Password.PasswordUnavailable.make({}))),
      checkReset: (input) =>
        store
          .read((state, now) => Effect.succeed(completionCurrent(state, input, now)))
          .pipe(Effect.catchTag("StoreUnavailable", () => Password.PasswordUnavailable.make({}))),
      resetWithProof: (input, prepare) =>
        store
          .transaction((state, journal, now) =>
            Effect.gen(function* () {
              if (
                input.authorization.challenge.action !== "reset-password" ||
                input.completion.input.binding._tag !== "Subject" ||
                input.completion.input.binding.revision.subjectId !==
                  input.expectedRevision.subjectId ||
                !completionCurrent(state, input.completion.input, now) ||
                !(yield* mutationCurrent(state, input)) ||
                state.mutations.some(
                  (item) => item.moduleId === moduleId && item.commandId === input.commandId,
                )
              )
                return prepare("rejected", journal);
              const receipt = prepare("changed", journal);

              const expiresAt =
                state.continuations.find(
                  (row) =>
                    row.id === input.completion.input.continuationId &&
                    row.moduleId === input.completion.input.moduleId,
                )?.expiresAt ?? 0;

              journal.beforeCommit(
                (time) =>
                  time >= now &&
                  time <
                    Math.min(
                      expiresAt,
                      evidenceDeadline(
                        input.authorization.evidence,
                        input.authorization.requirement,
                      ),
                    ),
              );
              input.completion.prepare("completed", journal, () => undefined);
              consumeCompletion(state, input.completion.input);
              replace(state, input);
              state.mutations = [
                ...state.mutations,
                {
                  moduleId,
                  commandId: input.commandId,
                  subjectId: input.expectedRevision.subjectId,
                  kind: "password",
                  retentionUntil: now + 3_600_000,
                },
              ];

              return receipt;
            }),
          )
          .pipe(Effect.mapError(() => Password.PasswordUnavailable.make({}))),
    });

    return Context.make(Password.PasswordPersistence, passwords).pipe(
      Context.add(AppAuth.strategies.password.RegistrationAuthority, {
        register: (input, prepare) =>
          store
            .transaction((state, journal) =>
              Effect.gen(function* () {
                if (input.moduleId !== moduleId || input.identifier.namespace !== "email")
                  return yield* Password.PasswordUnavailable.make({});
                // A public request ID never adopts an old subject or replaces its password.
                if (
                  state.registrations.some((item) => item.requestId === input.requestId) ||
                  state.customers.some(
                    (item) =>
                      item.email === input.identifier.value ||
                      item.username === input.registration.username,
                  )
                )
                  return prepare({ _tag: "Suppressed" }, journal);
                const subjectId = AuthSchema.SubjectId.make(nextId(state, "customer"));

                const email = yield* Schema.decodeEffect(AuthSchema.Email)(
                  input.identifier.value,
                ).pipe(Effect.mapError(() => Password.PasswordUnavailable.make({})));

                const receipt = prepare({ _tag: "Created", subjectId }, journal);

                state.customers = [
                  ...state.customers,
                  {
                    id: subjectId,
                    email,
                    active: true,
                    displayName: input.registration.displayName,
                    username: input.registration.username,
                    securityRevision: Sessions.SecurityRevision.make(nextId(state, "security")),
                    identifierRevision: Sessions.SecurityRevision.make(nextId(state, "identifier")),
                  },
                ];
                state.passwords = [
                  ...state.passwords,
                  {
                    subjectId,
                    credentialId: nextId(state, "password"),
                    replacement: input.replacement,
                    revision: Sessions.SecurityRevision.make(nextId(state, "password-revision")),
                    verifierVersion: Sessions.SecurityRevision.make(nextId(state, "verifier")),
                  },
                ];
                state.registrations = [
                  ...state.registrations,
                  {
                    requestId: input.requestId,
                    identifier: input.identifier,
                    registration: input.registration,
                    replacement: input.replacement,
                  },
                ];

                return receipt;
              }),
            )
            .pipe(Effect.catchTag("StoreUnavailable", () => Password.PasswordUnavailable.make({}))),
      }),
      Context.add(AppAuth.strategies.password.SessionClaims, {
        resolve: ({ subjectId, credential }) =>
          store
            .read((state) =>
              Effect.gen(function* () {
                const account = customer(state, subjectId);

                if (account === undefined || !current(state, credential.revision))
                  return yield* Password.PasswordUnavailable.make({});

                return claims(account);
              }),
            )
            .pipe(Effect.catchTag("StoreUnavailable", () => Password.PasswordUnavailable.make({}))),
      }),
    );
  }),
);
