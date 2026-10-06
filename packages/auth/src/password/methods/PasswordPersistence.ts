import { Context, type Effect, type Option, type Redacted } from "effect";

import type { CommitJournal, PreparedCommit } from "../../hooks/commit";
import type { LoginIdentifier } from "../../identity/models";
import type { ProofCompletionPlan } from "../../proofs/completion";
import type { ProofCompletionInput } from "../../proofs/ProofPersistence";
import type { SubjectId } from "../../Schema";
import type { SessionInvalidationWindow } from "../../sessions/invalidation";
import type { AuthenticationRevision, SecurityRevision } from "../../sessions/models";
import type { EncodedPasswordHash } from "../models";
import type { PasswordUnavailable } from "./errors";
import type {
  PasswordActionAuthorization,
  PasswordAttemptAdmission,
  PasswordAttemptDecision,
  PasswordAttemptId,
  PasswordCommandId,
  PasswordCredentialSnapshot,
  PasswordMutationDecision,
  PasswordReplacement,
} from "./models";

export type PreparePasswordCommit<Value, A> = (
  value: Value,
  journal: CommitJournal,
) => PreparedCommit<A>;

/** A captured candidate, before rate admission or credential verification.
 * The persistence owner retains native identifiers privately. Admission records
 * this snapshot; settlement must revalidate it before accepting the proof.
 */
export interface PasswordAttemptPreparation {
  readonly credential?: PasswordCredentialSnapshot;
  readonly admit: <A>(
    prepare: PreparePasswordCommit<PasswordAttemptAdmission, A>,
  ) => Effect.Effect<PreparedCommit<A>, PasswordUnavailable>;
}

export interface PasswordMutationInput {
  readonly moduleId: string;
  readonly commandId: PasswordCommandId;
  readonly expectedRevision: AuthenticationRevision;
  readonly credential?: PasswordCredentialSnapshot;
  readonly replacement: PasswordReplacement;
  readonly authorization: PasswordActionAuthorization;
  readonly invalidation: SessionInvalidationWindow;
}

/** Semantic authority. All mutations prepare before root physical commit and
 * join only an explicitly matching outer authority. Prepared method plans expose
 * a commit Effect that resolves its authority from Effect context at execution.
 * Provide the transaction-bound implementation there. A root service must reject ambient
 * use it cannot join before writes. No generic get/put/upsert.
 */
export class PasswordPersistence extends Context.Service<
  PasswordPersistence,
  {
    /** Read a coherent candidate without writing or holding a transaction open.
     * The strategy consumes action/identifier limits before this lookup and the
     * subject limit before admit. Unknown/disabled/missing return no verifier.
     * admit can execute once, records a single-use attempt, and resolves only after
     * owned commit. Failure or an unknown outcome does not authorize plan reuse.
     * Abandoned attempts expire; limit consumption is never refunded.
     */
    readonly prepareAttempt: (input: {
      readonly moduleId: string;
      readonly action: "sign-in" | "change";
      readonly identifier: LoginIdentifier;
      readonly subjectId?: SubjectId;
      readonly attemptLifetimeMillis: number;
    }) => Effect.Effect<PasswordAttemptPreparation, PasswordUnavailable>;
    /** Single-use settlement. verified requires SAME captured semantic revisions and
     * attempt ownership. Rehash CAS includes old verifier/version, changes verifierVersion
     * only and never semantic/security revisions or a newer credential's counters.
     * A CAS miss cannot become unconditional replacement. This does NOT issue auth.
     * Later session approval compares this same subject securityRevision. Identifier
     * remove/rebind/verification changes that invalidate login MUST bump it atomically;
     * identifierBindingRevision alone is not represented in AuthenticationRevision.
     */
    readonly settleAttempt: <A>(
      input: {
        readonly moduleId: string;
        readonly attemptId: PasswordAttemptId;
        readonly captured?: PasswordCredentialSnapshot;
        readonly outcome: PasswordAttemptDecision;
        readonly rehash?: {
          readonly expectedVersion: SecurityRevision;
          readonly expectedVerifier: Redacted.Redacted<EncodedPasswordHash>;
          readonly nextVerifier: Redacted.Redacted<EncodedPasswordHash>;
        };
      },
      prepare: PreparePasswordCommit<PasswordAttemptDecision, A>,
    ) => Effect.Effect<PreparedCommit<A>, PasswordUnavailable>;
    readonly readForSubject: (input: {
      readonly moduleId: string;
      readonly subjectId: SubjectId;
    }) => Effect.Effect<Option.Option<PasswordCredentialSnapshot>, PasswordUnavailable>;
    /** Only eligible verified identifiers; return None for absent/inactive/ineligible. */
    readonly recoveryTarget: (input: {
      readonly moduleId: string;
      readonly identifier: LoginIdentifier;
    }) => Effect.Effect<Option.Option<PasswordCredentialSnapshot>, PasswordUnavailable>;
    /** Require absence, current revisions/action+factor policy/fresh clock. */
    readonly addIfAbsent: <A>(
      input: PasswordMutationInput,
      prepare: PreparePasswordCommit<PasswordMutationDecision, A>,
    ) => Effect.Effect<PreparedCommit<A>, PasswordUnavailable>;
    /** Exact credential CAS, current action policy/freshness; bump semantic credential
     * and subject security revisions + pending/session invalidation in SAME authority.
     */
    readonly replaceIfCurrent: <A>(
      input: PasswordMutationInput,
      prepare: PreparePasswordCommit<PasswordMutationDecision, A>,
    ) => Effect.Effect<PreparedCommit<A>, PasswordUnavailable>;
    /** Authoritative nonconsuming preflight before exposing new-password policy
     * results or doing KDF work. Final resetWithProof repeats every predicate/CAS.
     */
    readonly checkReset: (
      input: ProofCompletionInput,
    ) => Effect.Effect<boolean, PasswordUnavailable>;
    /** Compose proof predicates + replacement/invalidation atomically. Never call an
     * independently committing ProofPersistence.complete. completed iff ALL apply.
     * D1 preplans before batch; exact lost guard discards success journal before a
     * separate zero-write rejected receipt. Unknown SQL failure remains unavailable.
     */
    readonly resetWithProof: <A>(
      input: PasswordMutationInput & { readonly completion: ProofCompletionPlan },
      prepare: PreparePasswordCommit<PasswordMutationDecision, A>,
    ) => Effect.Effect<PreparedCommit<A>, PasswordUnavailable>;
    readonly cleanupAttempts: <A>(
      input: { readonly moduleId: string; readonly limit: number },
      prepare: PreparePasswordCommit<{ readonly removed: number; readonly hasMore: boolean }, A>,
    ) => Effect.Effect<PreparedCommit<A>, PasswordUnavailable>;
  }
>()("effect-auth/PasswordPersistence") {}
