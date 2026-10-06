import { Context, type Effect, type Option, type Redacted } from "effect";

import type { CommitJournal, PreparedCommit } from "../../hooks/commit";
import type { LoginIdentifier } from "../../identity/models";
import type { ProofCompletionPlan } from "../../proofs/completion";
import type { ProofCompletionInput } from "../../proofs/ProofPersistence";
import type { SubjectId } from "../../Schema";
import type { SessionInvalidationWindow } from "../../sessions/invalidation";
import type { AuthenticationRevision } from "../../sessions/models";
import type { EncodedPasswordHash } from "../models";
import type { PasswordUnavailable } from "./errors";
import type {
  PasswordActionAuthorization,
  PasswordCommandId,
  PasswordCredentialSnapshot,
  PasswordMutationDecision,
  PasswordReplacement,
} from "./models";

export type PreparePasswordCommit<Value, A> = (
  value: Value,
  journal: CommitJournal,
) => PreparedCommit<A>;

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
     * Unknown, disabled, missing, or ineligible identifiers return None.
     * Session issuance and password mutation recheck the captured authority.
     * Identifier removal, rebinding, or eligibility changes MUST bump the subject
     * security revision atomically: identifierBindingRevision is not part of
     * AuthenticationRevision. Native identifiers stay inside the adapter.
     */
    readonly findCredential: (input: {
      readonly moduleId: string;
      readonly identifier: LoginIdentifier;
      readonly subjectId?: SubjectId;
    }) => Effect.Effect<Option.Option<PasswordCredentialSnapshot>, PasswordUnavailable>;
    /** Conditional maintenance only when hash parameters change. Compare the exact
     * credential identity, semantic revision, verifier and verifierVersion; change
     * only verifier/version. A lost CAS is a no-op, never unconditional replacement.
     * This write grants no authority and must not advance semantic/security revisions.
     */
    readonly rehashIfCurrent: (input: {
      readonly credential: PasswordCredentialSnapshot;
      readonly nextVerifier: Redacted.Redacted<EncodedPasswordHash>;
    }) => Effect.Effect<void, PasswordUnavailable>;
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
  }
>()("effect-auth/PasswordPersistence") {}
