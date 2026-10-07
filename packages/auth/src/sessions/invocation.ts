import { Context, Effect, type Redacted } from "effect";

import type { AuthInvocation } from "../operations/context";
import type { SubjectId } from "../Schema";
import type { SessionId } from "./models";

interface VerifiedSession {
  readonly moduleId: string;
  readonly credential: Redacted.Redacted<string>;
  readonly subjectId: SubjectId;
  readonly sessionId: SessionId;
  /** Detached private schema encoding, never a public operation result. */
  readonly inspection: string;
}

/** Only active while resolving the caller for one bound method invocation. */
export class SessionVerificationCapture extends Context.Service<
  SessionVerificationCapture,
  { readonly capture: (session: VerifiedSession) => void }
>()("effect-auth/internal/SessionVerificationCapture") {}

export class CurrentSessionInvocation extends Context.Service<
  CurrentSessionInvocation,
  {
    readonly invocation: AuthInvocation;
    readonly sessions: ReadonlyArray<VerifiedSession>;
    readonly isActive: () => boolean;
  }
>()("effect-auth/internal/CurrentSessionInvocation") {}

/** Reuse the verification that admitted this action only as its source evidence.
 * Explicit session reads still verify afresh; a later action resolves again. */
export const withSessionInvocation = <A, E, R, E2, R2>(
  resolve: Effect.Effect<AuthInvocation, E2, R2>,
  use: (invocation: AuthInvocation) => Effect.Effect<A, E, R>,
) =>
  Effect.gen(function* () {
    const sessions: VerifiedSession[] = [];
    let capturing = true;

    const invocation = yield* resolve.pipe(
      Effect.provideService(SessionVerificationCapture, {
        capture: (session) => {
          if (capturing) sessions.push(session);
        },
      }),
      Effect.onExit((exit) =>
        Effect.sync(() => {
          capturing = false;
          if (exit._tag === "Failure") sessions.length = 0;
        }),
      ),
    );

    let active = true;

    return yield* Effect.suspend(() => use(invocation)).pipe(
      Effect.provideService(CurrentSessionInvocation, {
        invocation,
        sessions,
        isActive: () => active,
      }),
      Effect.ensuring(
        Effect.sync(() => {
          active = false;
          sessions.length = 0;
        }),
      ),
    );
  });
