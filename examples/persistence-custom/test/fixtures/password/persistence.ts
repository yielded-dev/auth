import {
  coordinateCommit,
  hasCommitScope,
  LifecycleHooks,
  type CommitJournal,
} from "@yielded/auth/Hooks";
import {
  PasswordAttemptId,
  PasswordCredentialSnapshot,
  PasswordHashing,
  PasswordPersistence,
  PasswordUnavailable,
  type EncodedPasswordHash,
} from "@yielded/auth/Password";
import { SubjectId } from "@yielded/auth/Schema";
import {
  AuthenticationAuthority,
  assessAuthentication,
  SecurityRevision,
  SessionConflict,
  SessionId,
  SessionInvalid,
  SessionUnavailable,
  StaleAuthentication,
  type AuthenticationEvidence,
  type AuthenticationRevision,
  type StatefulSessionRecord,
} from "@yielded/auth/Sessions";
import { Context, DateTime, Effect, Layer, Option, Redacted, Semaphore } from "effect";

import type { Claims } from "./auth";
import { AppAuth, requirement } from "./auth";

export const customerId = SubjectId.make("customer-001");
export const email = "dan@example.invalid";
export const password = "A long example passphrase for this customer";
const credentialId = "password-001";
const credentialRevision = SecurityRevision.make("password-r1");
const moduleId = AppAuth.strategies.password.persistence.moduleId;

type Session = StatefulSessionRecord<typeof Claims.Type>;

interface Attempt {
  readonly captured?: PasswordCredentialSnapshot;
  readonly pending: boolean;
  readonly deadline: number;
  readonly retentionUntil: number;
}
interface Charge {
  readonly attemptId: PasswordAttemptId;
  readonly identifier: string;
  readonly subject?: SubjectId;
  readonly at: number;
}
interface State {
  active: boolean;
  revision: SecurityRevision;
  verifier: Redacted.Redacted<EncodedPasswordHash>;
  verifierVersion: SecurityRevision;
  sequence: number;
  readonly attempts: Map<PasswordAttemptId, Attempt>;
  readonly charges: Charge[];
  readonly sessions: Map<SessionId, Session>;
  readonly flows: Map<string, number>;
}

export class Customers extends Context.Service<
  Customers,
  {
    readonly disable: Effect.Effect<void, SessionUnavailable>;
  }
>()("example/Customers") {}

// One process, one lifetime, one transaction authority. State disappears when
// this Layer's scope closes. A durable adapter must implement these same ports
// with its own commit/rollback and unknown-outcome handling.
export const PersistenceLive = Layer.effectContext(
  Effect.gen(function* () {
    const hooks = yield* LifecycleHooks;
    const mutex = yield* Semaphore.make(1);
    const verifier = yield* (yield* PasswordHashing).hash(Redacted.make(password));

    let state: State = {
      active: true,
      revision: SecurityRevision.make("customer-r1"),
      verifier,
      verifierVersion: SecurityRevision.make("verifier-r1"),
      sequence: 0,
      attempts: new Map(),
      charges: [],
      sessions: new Map(),
      flows: new Map(),
    };

    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        state.active = false;
        state.sessions.clear();
        state.attempts.clear();
        state.charges.length = 0;
        state.flows.clear();
      }),
    );

    const atomic = <A, E, Failure>(
      unavailable: () => Failure,
      body: (next: State, journal: CommitJournal, now: DateTime.Utc) => Effect.Effect<A, E>,
    ) =>
      Effect.gen(function* () {
        // This authority cannot join an unrelated transaction.
        if (yield* hasCommitScope) return yield* Effect.fail(unavailable());

        const committed = yield* coordinateCommit(
          (journal) =>
            mutex.withPermits(1)(
              Effect.uninterruptible(
                Effect.gen(function* () {
                  const next: State = {
                    ...state,
                    attempts: new Map(state.attempts),
                    charges: [...state.charges],
                    sessions: new Map(state.sessions),
                    flows: new Map(state.flows),
                  };

                  const now = yield* DateTime.now;
                  const result = yield* body(next, journal, now);

                  // A single synchronous assignment is this model's commit point. Failed
                  // preparation, defects and interruption never publish the working copy.
                  state = next;

                  return result;
                }),
              ),
            ),
          { mode: "interactive" },
        ).pipe(Effect.catchTag("HookConfigurationError", () => Effect.fail(unavailable())));

        return committed.value;
      }).pipe(Effect.provideService(LifecycleHooks, hooks));

    const revision = (current: State): AuthenticationRevision => ({
      subjectId: customerId,
      securityRevision: current.revision,
      credentials: [{ credentialId, revision: credentialRevision }],
    });

    const current = (snapshot: AuthenticationRevision, s: State) =>
      s.active &&
      snapshot.subjectId === customerId &&
      snapshot.securityRevision === s.revision &&
      snapshot.credentials.every(
        (c) => c.credentialId === credentialId && c.revision === credentialRevision,
      );

    const credential = (s: State) =>
      PasswordCredentialSnapshot.make({
        moduleId,
        revision: revision(s),
        credentialId,
        credentialRevision,
        verifierVersion: s.verifierVersion,
        verifier: s.verifier,
        normalization: "none",
        identifier: { namespace: "email", value: email },
        identifierBindingRevision: SecurityRevision.make("email-r1"),
        identifierVerifiedAtMillis: 1,
      });

    const checkEvidence = (evidence: AuthenticationEvidence, s: State, _now: DateTime.Utc) =>
      Effect.gen(function* () {
        if (!current(evidence.revision, s)) return yield* StaleAuthentication.make({});

        const assessment = yield* assessAuthentication(evidence, requirement).pipe(
          Effect.catchTag("SessionConfigurationError", () =>
            Effect.fail(SessionUnavailable.make({})),
          ),
        );

        if (!assessment.satisfied) return yield* StaleAuthentication.make({});
      });

    const validSession = (row: Session, s: State, now: number) =>
      s.active &&
      row.subjectId === customerId &&
      row.securityRevision === s.revision &&
      now <
        Math.min(
          DateTime.toEpochMillis(row.expiresAt),
          DateTime.toEpochMillis(row.absoluteExpiresAt),
        );

    const authority = AuthenticationAuthority.of({
      capture: (id, ids) =>
        Effect.suspend(() =>
          state.active && id === customerId && ids.every((id) => id === credentialId)
            ? Effect.succeed({
                ...revision(state),
                credentials: ids.map((id) => ({ credentialId: id, revision: credentialRevision })),
              })
            : Effect.fail(StaleAuthentication.make({})),
        ),
      requirements: (evidence) =>
        Effect.gen(function* () {
          yield* checkEvidence(evidence, state, yield* DateTime.now);

          return requirement;
        }),
      approve: (input, prepare) =>
        atomic(
          () => SessionUnavailable.make({}),
          (s, journal, now) =>
            Effect.gen(function* () {
              yield* checkEvidence(input.evidence, s, now);
              if (
                input.pending !== undefined ||
                DateTime.toEpochMillis(now) >=
                  Math.min(
                    DateTime.toEpochMillis(input.expiresAt),
                    DateTime.toEpochMillis(input.absoluteExpiresAt),
                  )
              )
                return yield* StaleAuthentication.make({});

              return prepare(undefined, journal);
            }),
        ),
    });

    const passwords = PasswordPersistence.of({
      admitAttempt: (input, prepare) =>
        atomic(
          () => PasswordUnavailable.make({}),
          (s, journal, time) =>
            Effect.sync(() => {
              if (input.moduleId !== moduleId || input.action !== "sign-in")
                return prepare({ _tag: "Denied" }, journal);
              const now = DateTime.toEpochMillis(time);
              const identifier = input.identifier.namespace + "/" + input.identifier.value;

              const found =
                s.active &&
                input.identifier.namespace === "email" &&
                input.identifier.value === email &&
                (input.subjectId === undefined || input.subjectId === customerId)
                  ? credential(s)
                  : undefined;

              const scopes = [
                { ...input.policy.action, matches: () => true },
                {
                  ...input.policy.identifier,
                  matches: (charge: Charge) => charge.identifier === identifier,
                },
                ...(found === undefined
                  ? []
                  : [
                      {
                        ...input.policy.subject,
                        matches: (charge: Charge) => charge.subject === customerId,
                      },
                    ]),
              ];

              if (
                scopes.some(
                  (scope) =>
                    s.charges.filter(
                      (charge) => scope.matches(charge) && charge.at > now - scope.windowMillis,
                    ).length >= scope.limit,
                ) ||
                [...s.attempts.values()].filter(
                  (attempt) => attempt.pending && attempt.deadline > now,
                ).length >= input.policy.maximumPending
              )
                return prepare({ _tag: "Denied" }, journal);
              const attemptId = PasswordAttemptId.make(`attempt-${++s.sequence}`);

              const receipt = prepare(
                {
                  _tag: "Admitted",
                  attemptId,
                  ...(found === undefined ? {} : { credential: found }),
                },
                journal,
              );

              s.attempts.set(attemptId, {
                captured: found,
                pending: true,
                deadline: now + input.policy.attemptLifetimeMillis,
                retentionUntil:
                  now +
                  Math.max(
                    input.policy.attemptLifetimeMillis,
                    ...scopes.map((scope) => scope.windowMillis),
                  ),
              });
              s.charges.push({
                attemptId,
                identifier,
                subject: found?.revision.subjectId,
                at: now,
              });

              return receipt;
            }),
        ),
      settleAttempt: (input, prepare) =>
        atomic(
          () => PasswordUnavailable.make({}),
          (s, journal, time) =>
            Effect.sync(() => {
              const attempt = s.attempts.get(input.attemptId);
              const captured = input.captured;
              const saved = attempt?.captured;

              const verified =
                input.moduleId === moduleId &&
                input.outcome === "verified" &&
                attempt?.pending === true &&
                attempt.deadline > DateTime.toEpochMillis(time) &&
                captured !== undefined &&
                saved !== undefined &&
                current(captured.revision, s) &&
                captured.credentialId === saved.credentialId &&
                captured.credentialRevision === saved.credentialRevision &&
                captured.verifierVersion === saved.verifierVersion &&
                captured.identifierBindingRevision === saved.identifierBindingRevision &&
                captured.identifier.namespace === saved.identifier.namespace &&
                captured.identifier.value === saved.identifier.value &&
                Redacted.value(captured.verifier) === Redacted.value(saved.verifier);

              const receipt = prepare(verified ? "verified" : "rejected", journal);

              if (attempt !== undefined)
                s.attempts.set(input.attemptId, { ...attempt, pending: false });
              if (
                verified &&
                input.rehash !== undefined &&
                s.verifierVersion === input.rehash.expectedVersion &&
                Redacted.value(s.verifier) === Redacted.value(input.rehash.expectedVerifier)
              ) {
                s.verifier = input.rehash.nextVerifier;
                s.verifierVersion = SecurityRevision.make(`verifier-${++s.sequence}`);
              }

              return receipt;
            }),
        ),
      readForSubject: (input) =>
        Effect.sync(() =>
          sMatch(input.moduleId, input.subjectId) ? Option.some(credential(state)) : Option.none(),
        ),
      recoveryTarget: () => Effect.fail(PasswordUnavailable.make({})),
      addIfAbsent: () => Effect.fail(PasswordUnavailable.make({})),
      replaceIfCurrent: () => Effect.fail(PasswordUnavailable.make({})),
      checkReset: () => Effect.fail(PasswordUnavailable.make({})),
      resetWithProof: () => Effect.fail(PasswordUnavailable.make({})),
      cleanupAttempts: (input, prepare) =>
        atomic(
          () => PasswordUnavailable.make({}),
          (s, journal, now) =>
            Effect.sync(() => {
              const expired =
                input.moduleId === moduleId
                  ? [...s.attempts].filter(
                      ([, row]) => row.retentionUntil <= DateTime.toEpochMillis(now),
                    )
                  : [];

              const remove = expired.slice(0, input.limit);

              const receipt = prepare(
                { removed: remove.length, hasMore: expired.length > remove.length },
                journal,
              );

              for (const [id] of remove) s.attempts.delete(id);
              const retained = s.charges.filter((charge) => s.attempts.has(charge.attemptId));

              s.charges.splice(0, s.charges.length, ...retained);

              return receipt;
            }),
        ),
    });

    const sMatch = (id: string, subject: SubjectId) =>
      id === moduleId && subject === customerId && state.active;

    const sessions = AppAuth.sessions.StatefulSessionPersistence.of({
      establish: (input, prepare) =>
        atomic(
          () => SessionUnavailable.make({}),
          (s, journal, now) =>
            Effect.gen(function* () {
              yield* checkEvidence(input.evidence, s, now);
              const millis = DateTime.toEpochMillis(now);

              if (
                (s.flows.get(input.evidence.flowId) ?? 0) > millis ||
                [...s.sessions.values()].some((row) => row.digest === input.session.digest)
              )
                return yield* SessionConflict.make({});
              if (
                input.pending !== undefined ||
                millis >=
                  Math.min(
                    DateTime.toEpochMillis(input.session.expiresAt),
                    DateTime.toEpochMillis(input.session.absoluteExpiresAt),
                  )
              )
                return yield* StaleAuthentication.make({});

              const row: Session = {
                ...input.session,
                sessionId: SessionId.make(`session-${++s.sequence}`),
                version: SecurityRevision.make(`session-version-${s.sequence}`),
              };

              const receipt = prepare(row, journal);

              s.sessions.set(row.sessionId, row);
              s.flows.set(input.evidence.flowId, DateTime.toEpochMillis(row.absoluteExpiresAt));

              return receipt;
            }),
        ),
      verify: (input) =>
        Effect.gen(function* () {
          const now = DateTime.toEpochMillis(yield* DateTime.now);
          const row = [...state.sessions.values()].find((row) => row.digest === input.digest);

          if (row === undefined || !validSession(row, state, now))
            return yield* SessionInvalid.make({});

          return row;
        }),
      rotate: (input, prepare) =>
        atomic(
          () => SessionUnavailable.make({}),
          (s, journal, now) =>
            Effect.gen(function* () {
              const row = s.sessions.get(input.sessionId);

              if (
                row === undefined ||
                !validSession(row, s, DateTime.toEpochMillis(now)) ||
                row.digest !== input.expectedDigest ||
                row.version !== input.expectedVersion ||
                row.securityRevision !== input.expectedSecurityRevision ||
                DateTime.toEpochMillis(input.nextExpiresAt) <= DateTime.toEpochMillis(now) ||
                DateTime.toEpochMillis(input.nextExpiresAt) >
                  DateTime.toEpochMillis(row.absoluteExpiresAt) ||
                [...s.sessions.values()].some((other) => other.digest === input.nextDigest)
              )
                return yield* SessionConflict.make({});

              const next = {
                ...row,
                digest: input.nextDigest,
                credentialVersion: input.nextCredentialVersion,
                issuedAt: now,
                expiresAt: input.nextExpiresAt,
                version: SecurityRevision.make(`session-version-${++s.sequence}`),
              };

              const receipt = prepare(next, journal);

              s.sessions.set(next.sessionId, next);

              return receipt;
            }),
        ),
      revokeDigest: (digest, prepare) =>
        atomic(
          () => SessionUnavailable.make({}),
          (s, journal) =>
            Effect.sync(() => {
              const row = [...s.sessions.values()].find((row) => row.digest === digest);
              const receipt = prepare(row !== undefined, journal);

              if (row !== undefined) s.sessions.delete(row.sessionId);

              return receipt;
            }),
        ),
      revoke: (input, prepare) =>
        atomic(
          () => SessionUnavailable.make({}),
          (s, journal) =>
            Effect.gen(function* () {
              if (
                !s.active ||
                input.subjectId !== customerId ||
                input.expectedSecurityRevision !== s.revision
              )
                return yield* StaleAuthentication.make({});
              const receipt = prepare(undefined, journal);

              s.sessions.delete(input.sessionId);

              return receipt;
            }),
        ),
      revokeAll: (input, prepare) =>
        atomic(
          () => SessionUnavailable.make({}),
          (s, journal) =>
            Effect.gen(function* () {
              if (
                !s.active ||
                input.subjectId !== customerId ||
                input.expectedSecurityRevision !== s.revision
              )
                return yield* StaleAuthentication.make({});
              const receipt = prepare(undefined, journal);

              s.revision = SecurityRevision.make(`customer-${++s.sequence}`);
              s.sessions.clear();

              return receipt;
            }),
        ),
    });

    return Context.make(PasswordPersistence, passwords).pipe(
      Context.add(AuthenticationAuthority, authority),
      Context.add(AppAuth.sessions.StatefulSessionPersistence, sessions),
      Context.add(AppAuth.sessions.SessionRepository, {
        list: (input) =>
          Effect.sync(() => {
            const rows = [...state.sessions.values()]
              .filter(
                (row) =>
                  row.subjectId === input.subjectId &&
                  validSession(row, state, DateTime.toEpochMillis(input.now)) &&
                  (input.cursor === undefined || row.sessionId > input.cursor),
              )
              .sort((a, b) => a.sessionId.localeCompare(b.sessionId));

            const page = rows.slice(0, input.limit);

            return {
              sessions: page.map(
                ({
                  sessionId,
                  subjectId,
                  securityRevision,
                  assurance,
                  issuedAt,
                  expiresAt,
                  absoluteExpiresAt,
                }) => ({
                  sessionId,
                  subjectId,
                  securityRevision,
                  assurance,
                  issuedAt,
                  expiresAt,
                  absoluteExpiresAt,
                }),
              ),
              ...(rows.length > page.length
                ? { nextCursor: page[page.length - 1]?.sessionId }
                : {}),
            };
          }),
      }),
      Context.add(AppAuth.strategies.password.ClaimsForPassword, {
        resolve: (captured) =>
          Effect.suspend(() =>
            current(captured.revision, state)
              ? Effect.succeed({ displayName: "Dan" })
              : Effect.fail(PasswordUnavailable.make({})),
          ),
      }),
      Context.add(Customers, {
        disable: atomic(
          () => SessionUnavailable.make({}),
          (s) =>
            Effect.sync(() => {
              s.active = false;
              s.revision = SecurityRevision.make(`customer-${++s.sequence}`);
              s.sessions.clear();
            }),
        ),
      }),
    );
  }),
).pipe(Layer.provide(LifecycleHooks.empty));
