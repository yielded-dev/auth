import {
  coordinateCommit,
  CurrentCommitJournal,
  hasCommitScope,
  LifecycleHooks,
} from "@yielded/auth/Hooks";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import type { SubjectId } from "@yielded/auth/Schema";
import {
  assessAuthentication,
  PendingAuthenticationInvalid,
  SessionConflict,
  SessionInvalid,
  SessionMetadata,
  SessionUnavailable,
  snapshotSessionAuthenticationProvenance,
  StaleAuthentication,
  type AuthenticationAuthority,
  type AuthenticationEvidence,
  type AuthenticationRevision,
  type PendingConsumption,
  type SessionRepository,
  type StatefulSessionPersistence,
  type StatefulSessionRecord,
} from "@yielded/auth/Sessions";
import { Cause, DateTime, Effect, Schema } from "effect";

import { isMappedConstraintConflict } from "./mapping-error";
import { allocateSessionValue, preservesRevision } from "./session-policy";
import type {
  SessionTransactionOwner,
  SessionWorkflowPolicy,
  SessionSqlOptions,
  SessionAuthorityReader,
  SessionAuthorityStore,
  SessionPendingStore,
  StatefulSessionStore,
} from "./session-store";

const unavailable = () => SessionUnavailable.make({});
const stale = () => StaleAuthentication.make({});
const invalidPending = () => PendingAuthenticationInvalid.make({});

type SessionFailure =
  | SessionConflict
  | SessionInvalid
  | SessionUnavailable
  | StaleAuthentication
  | PendingAuthenticationInvalid;

const expected = (error: unknown): error is SessionFailure =>
  Schema.is(SessionConflict)(error) ||
  Schema.is(SessionInvalid)(error) ||
  Schema.is(SessionUnavailable)(error) ||
  Schema.is(StaleAuthentication)(error) ||
  Schema.is(PendingAuthenticationInvalid)(error);

type Normalized<E> = E extends SessionFailure ? E : SessionUnavailable;

const safe = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  reportPersistenceFailure(effect, expected).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(
        Cause.map(cause, (error): Normalized<E> | SessionUnavailable =>
          expected(error) ? (error as Normalized<E>) : unavailable(),
        ),
      ),
    ),
  );

export const captureSessionAuthority = Effect.fnUntraced(function* (
  store: SessionAuthorityReader,
  subjectId: SubjectId,
  credentialIds: ReadonlyArray<string>,
  locking: boolean,
  flowId?: string,
) {
  const requested = [...new Set(credentialIds)].sort();

  if (requested.length !== credentialIds.length) return yield* stale();
  const current = yield* store.readAuthority(subjectId, requested, locking, flowId);

  const credentials = current.credentials.filter((credential) => credential.active);

  if (
    current.subject === undefined ||
    !current.subject.active ||
    current.credentials.length > 4096 ||
    credentials.length > 64 ||
    new Set(current.credentials.map((credential) => credential.credentialId)).size !==
      current.credentials.length ||
    requested.some((id) => !credentials.some((credential) => credential.credentialId === id))
  )
    return yield* stale();

  const revision: AuthenticationRevision = {
    subjectId,
    securityRevision: current.subject.securityRevision,
    credentials: credentials
      .map(({ credentialId, revision }) => ({ credentialId, revision }))
      .sort((a, b) => a.credentialId.localeCompare(b.credentialId)),
  };

  return { ...current, subject: current.subject, revision };
});

export const sessionEvidenceRequirement = Effect.fnUntraced(function* (
  store: SessionAuthorityReader,
  evidence: AuthenticationEvidence,
  locking: boolean,
  flowId?: string,
) {
  const current = yield* captureSessionAuthority(
    store,
    evidence.revision.subjectId,
    evidence.revision.credentials.map((credential) => credential.credentialId),
    locking,
    flowId,
  );

  const expectedCredentials = [...evidence.revision.credentials].sort((a, b) =>
    a.credentialId.localeCompare(b.credentialId),
  );

  if (
    current.revision.securityRevision !== evidence.revision.securityRevision ||
    current.revision.credentials.length !== expectedCredentials.length ||
    current.revision.credentials.some(
      (credential, index) =>
        credential.credentialId !== expectedCredentials[index]?.credentialId ||
        credential.revision !== expectedCredentials[index]?.revision,
    )
  )
    return yield* stale();

  return { requirement: yield* current.subject.requirement, flow: current.flow };
});

export const readSessionPending = Effect.fnUntraced(function* <Claims>(
  store: SessionPendingStore<Claims> | undefined,
  input: PendingConsumption,
) {
  if (store === undefined) return yield* invalidPending();
  const selected = yield* store.lockPending(input.digest);

  if (selected === undefined) return yield* invalidPending();
  const { record, flow } = selected;

  if (
    record.version !== input.version ||
    record.evidence.flowId !== input.flowId ||
    record.evidence.bindingDigest !== input.bindingDigest ||
    selected.consumed ||
    selected.failedAttempts >= record.attemptLimit ||
    flow === undefined ||
    !flow.pending ||
    flow.pendingDigest !== input.digest ||
    DateTime.toEpochMillis(yield* DateTime.now) >= DateTime.toEpochMillis(record.expiresAt)
  )
    return yield* invalidPending();

  return record;
});

export const ownSessionCommit = <Store, A, E, R>(
  owner: SessionTransactionOwner<Store>,
  options: SessionSqlOptions,
  isConstraintConflict: (cause: unknown) => boolean,
  body: (store: Store) => Effect.Effect<A, E, R | CurrentCommitJournal>,
) =>
  Effect.gen(function* () {
    if (!(yield* owner.isCurrent)) {
      if (yield* hasCommitScope) return yield* unavailable();
      yield* options.standaloneGuard;
    }

    return yield* coordinateCommit(() => owner.transaction(body)).pipe(
      (effect) =>
        reportPersistenceFailure(
          effect,
          (error) => expected(error) || isMappedConstraintConflict(isConstraintConflict, error),
        ),
      Effect.map((committed) => committed.value),
      Effect.catchCause((cause) =>
        Effect.failCause(
          Cause.map(cause, (error): Normalized<E> | SessionUnavailable =>
            expected(error) ? (error as Normalized<E>) : unavailable(),
          ),
        ),
      ),
    );
  });

export const makeAuthenticationAuthorityWorkflow = Effect.fnUntraced(function* <Claims>(
  mapping: Pick<SessionWorkflowPolicy<unknown>, "isConstraintConflict">,
  options: SessionSqlOptions,
  owner: SessionTransactionOwner<SessionAuthorityStore<Claims>>,
) {
  const hooks = yield* LifecycleHooks;

  const service: AuthenticationAuthority["Service"] = {
    capture: (subjectId, credentialIds) =>
      safe(
        captureSessionAuthority(
          owner.read,
          subjectId,
          credentialIds,
          options.coordinated === true && options.locking,
        ).pipe(
          Effect.flatMap((current) =>
            Effect.map(current.subject.requirement, (requirement) => ({
              revision: current.revision,
              requirement,
            })),
          ),
        ),
      ).pipe(Effect.provideService(LifecycleHooks, hooks)),
    requirements: (evidence) =>
      safe(
        sessionEvidenceRequirement(
          owner.read,
          evidence,
          options.coordinated === true && options.locking,
        ).pipe(Effect.map((current) => current.requirement)),
      ).pipe(Effect.provideService(LifecycleHooks, hooks)),
    approve: (input, prepare) =>
      ownSessionCommit(owner, options, mapping.isConstraintConflict, (store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;

          const { requirement } = yield* sessionEvidenceRequirement(
            store,
            input.evidence,
            options.locking,
          );

          let pendingExpiresAt: DateTime.Utc | undefined;

          if (input.pending !== undefined) {
            const pending = yield* readSessionPending(store.pending, input.pending);

            if (!preservesRevision(input.evidence, pending.evidence))
              return yield* invalidPending();
            pendingExpiresAt = pending.expiresAt;
          }

          const assessed = yield* assessAuthentication(input.evidence, requirement).pipe(
            Effect.mapError(unavailable),
          );

          const now = yield* DateTime.now;

          if (
            !assessed.satisfied ||
            (pendingExpiresAt !== undefined &&
              DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(pendingExpiresAt)) ||
            DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(input.expiresAt) ||
            DateTime.toEpochMillis(input.expiresAt) >
              DateTime.toEpochMillis(input.absoluteExpiresAt)
          )
            return yield* stale();
          const receipt = prepare(undefined, journal);

          if (input.pending !== undefined) {
            if (store.pending === undefined) return yield* invalidPending();
            yield* store.pending.consumePending(input.pending, input.absoluteExpiresAt);
          }

          return receipt;
        }),
      ).pipe(Effect.provideService(LifecycleHooks, hooks)),
  };

  return service;
});

export const makeStatefulSessionWorkflow = Effect.fnUntraced(function* <Claims, NativeSessionId>(
  mapping: SessionWorkflowPolicy<NativeSessionId>,
  options: SessionSqlOptions,
  owner: SessionTransactionOwner<StatefulSessionStore<Claims>>,
) {
  const hooks = yield* LifecycleHooks;

  const owned = <A, E, R>(body: (store: StatefulSessionStore<Claims>) => Effect.Effect<A, E, R>) =>
    ownSessionCommit(owner, options, mapping.isConstraintConflict, body).pipe(
      Effect.provideService(LifecycleHooks, hooks),
    );

  const persistence: StatefulSessionPersistence<Claims> = {
    establish: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;

          const { requirement, flow } = yield* sessionEvidenceRequirement(
            store,
            input.evidence,
            options.locking,
            input.pending === undefined ? input.evidence.flowId : undefined,
          );

          let pendingExpiresAt: DateTime.Utc | undefined;

          if (input.pending === undefined) {
            if (
              flow !== undefined &&
              DateTime.toEpochMillis(yield* DateTime.now) < DateTime.toEpochMillis(flow.dedupUntil)
            )
              return yield* SessionConflict.make({});
          } else {
            const pending = yield* readSessionPending(store.pending, input.pending);

            if (!preservesRevision(input.evidence, pending.evidence))
              return yield* invalidPending();
            pendingExpiresAt = pending.expiresAt;
          }

          const nativeSessionId = yield* allocateSessionValue(
            options.mode,
            mapping.session.allocateId,
            mapping.session.allocateIdSync,
          );

          const sessionId = yield* mapping.sessionId.toSession(nativeSessionId);

          if (sessionId === input.handoffSourceSessionId) return yield* SessionConflict.make({});

          const version = yield* allocateSessionValue(
            options.mode,
            mapping.session.allocateVersion,
            mapping.session.allocateVersionSync,
          );

          const assessed = yield* assessAuthentication(input.evidence, requirement);
          const now = yield* DateTime.now;

          if (
            !assessed.satisfied ||
            (pendingExpiresAt !== undefined &&
              DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(pendingExpiresAt)) ||
            DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(input.session.expiresAt) ||
            DateTime.toEpochMillis(input.session.expiresAt) >
              DateTime.toEpochMillis(input.session.absoluteExpiresAt)
          )
            return yield* stale();

          const record: StatefulSessionRecord<Claims> = {
            ...input.session,
            sessionId,
            version,
            subjectId: input.evidence.revision.subjectId,
            securityRevision: input.evidence.revision.securityRevision,
            assurance:
              input.handoffSourceSessionId === undefined
                ? assessed.assurance
                : input.session.assurance,
            provenance: yield* snapshotSessionAuthenticationProvenance({
              evidence: input.evidence,
            }),
            issuedAt: now,
          };

          const receipt = prepare(record, journal);

          yield* store.establish(
            record,
            input.evidence,
            input.pending,
            flow !== undefined,
            nativeSessionId,
          );
          const commitNow = yield* DateTime.now;

          if (
            DateTime.toEpochMillis(commitNow) < DateTime.toEpochMillis(record.issuedAt) ||
            DateTime.toEpochMillis(commitNow) >= DateTime.toEpochMillis(record.expiresAt) ||
            !(yield* assessAuthentication(input.evidence, requirement)).satisfied
          )
            return yield* stale();

          return receipt;
        }).pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(
              Cause.map(cause, (error) =>
                isMappedConstraintConflict(mapping.isConstraintConflict, error)
                  ? SessionConflict.make({})
                  : error,
              ),
            ),
          ),
        ),
      ),
    verify: (input) =>
      safe(
        Effect.gen(function* () {
          const selected = yield* owner.read.readForVerification(input.digest);

          if (selected === undefined) return yield* SessionInvalid.make({});
          const { record, authority } = selected;
          const now = yield* DateTime.now;

          if (
            authority === undefined ||
            !authority.active ||
            authority.securityRevision !== record.securityRevision ||
            DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(record.expiresAt) ||
            DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(record.absoluteExpiresAt)
          )
            return yield* SessionInvalid.make({});

          return record;
        }),
      ).pipe(Effect.provideService(LifecycleHooks, hooks)),
    rotate: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;
          const selected = yield* store.lockRotation(input.sessionId);

          if (selected === undefined) return yield* SessionConflict.make({});
          const { record, authority } = selected;

          const version = yield* allocateSessionValue(
            options.mode,
            mapping.session.allocateVersion,
            mapping.session.allocateVersionSync,
          );

          const now = yield* DateTime.now;

          if (
            authority === undefined ||
            !authority.active ||
            authority.securityRevision !== input.expectedSecurityRevision ||
            record.securityRevision !== input.expectedSecurityRevision ||
            record.digest !== input.expectedDigest ||
            record.version !== input.expectedVersion ||
            DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(record.expiresAt) ||
            DateTime.toEpochMillis(now) >= DateTime.toEpochMillis(record.absoluteExpiresAt) ||
            DateTime.toEpochMillis(input.nextExpiresAt) >
              DateTime.toEpochMillis(record.absoluteExpiresAt) ||
            DateTime.toEpochMillis(input.nextExpiresAt) <= DateTime.toEpochMillis(now)
          )
            return yield* SessionConflict.make({});

          const next = {
            ...record,
            digest: input.nextDigest,
            credentialVersion: input.nextCredentialVersion,
            version,
            issuedAt: now,
            expiresAt: input.nextExpiresAt,
          };

          const receipt = prepare(next, journal);

          yield* store.rotate(input, next);

          return receipt;
        }),
      ),
    revokeDigest: (digest, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;
          const present = yield* store.lockDigest(digest);
          const receipt = prepare(present, journal);

          if (present) yield* store.revokeDigest(digest);

          return receipt;
        }),
      ),
    revoke: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;
          const subject = yield* store.readSubject(input.subjectId, true);

          if (
            subject === undefined ||
            !subject.active ||
            subject.securityRevision !== input.expectedSecurityRevision
          )
            return yield* stale();
          const receipt = prepare(undefined, journal);

          yield* store.revoke(input);

          return receipt;
        }),
      ),
    revokeAll: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;
          const subject = yield* store.readSubject(input.subjectId, true);

          if (
            subject === undefined ||
            !subject.active ||
            subject.securityRevision !== input.expectedSecurityRevision
          )
            return yield* stale();
          const nextRevisionSync = mapping.subject.nextSecurityRevisionSync;

          const next = yield* allocateSessionValue(
            options.mode,
            mapping.subject.nextSecurityRevision?.(input.expectedSecurityRevision),
            nextRevisionSync === undefined
              ? undefined
              : () => nextRevisionSync(input.expectedSecurityRevision),
          );

          const receipt = prepare(undefined, journal);

          yield* store.revokeAll(input, next);

          return receipt;
        }),
      ),
  };

  const repository: SessionRepository = {
    list: (input) =>
      safe(
        owner.transaction((store) =>
          Effect.gen(function* () {
            const subject = yield* store.readSubject(input.subjectId, false);

            if (subject === undefined || !subject.active) return { sessions: [] };

            const decoded = yield* store.readPage({
              ...input,
              securityRevision: subject.securityRevision,
              now: yield* DateTime.now,
              limit: input.limit + 1,
            });

            const codec = Schema.toCodecJson(Schema.toType(SessionMetadata));

            const sessions = yield* Effect.forEach(decoded.slice(0, input.limit), (record) =>
              Schema.encodeEffect(codec)(record).pipe(Effect.flatMap(Schema.decodeEffect(codec))),
            );

            const nextCursor =
              decoded[input.limit] === undefined ? undefined : sessions.at(-1)?.sessionId;

            return { sessions, ...(nextCursor === undefined ? {} : { nextCursor }) };
          }),
        ),
      ).pipe(Effect.provideService(LifecycleHooks, hooks)),
  };

  return { statefulSessionPersistence: persistence, sessionRepository: repository };
});
