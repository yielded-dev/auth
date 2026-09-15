import { Context, Crypto, Effect, Layer, Schema, type Types } from "effect";

import { makeAuthStrategy } from "../../auth/AuthStrategy";
import { cryptoLayer } from "../../auth/defaults";
import { HookDenied } from "../../hooks/models";
import type { AuthInvocation } from "../../operations/context";
import { makeOperation, operationGroup } from "../../operations/operation";
import { AuthenticationFlowId } from "../../sessions/models";
import type { makeSessionModule } from "../../sessions/module";
import { hashingLayer } from "../defaults";
import { PasswordSignInInput } from "./contracts";
import {
  PasswordMethodConfigurationError,
  PasswordMethodUnsupported,
  PasswordRejected,
  PasswordUnavailable,
} from "./errors";
import type { PasswordCredentialSnapshot } from "./models";
import {
  defaultPasswordMethodPolicy,
  snapshotPasswordMethodPolicy,
  validatePasswordMethodPolicy,
  type PasswordMethodPolicy,
} from "./policy";
import { snapshotPasswordCredential } from "./snapshot";
import {
  makePasswordVerification,
  readPasswordCommit,
  passwordCompletionFailure,
} from "./verification";

export interface PasswordSignInOptions<
  SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
> {
  readonly sessions: ReturnType<typeof makeSessionModule<SessionId, Claims>>;
  readonly policy?: PasswordMethodPolicy;
  readonly features?: { readonly signIn: true };
}

/** A sign-in-only installation never acquires account creation or password mutation services. */
export const makePasswordSignIn = <
  const Id extends string,
  const SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
>(
  moduleId: Id,
  options: PasswordSignInOptions<SessionId, Claims>,
) => {
  const { sessions } = options;
  const source = options.policy ?? defaultPasswordMethodPolicy;
  const policy = validatePasswordMethodPolicy(snapshotPasswordMethodPolicy(source));

  const ClaimsForPassword = Context.Service<
    {
      readonly moduleId: Id;
      readonly kind: "claims";
      readonly claims: Types.Invariant<Claims["Type"]>;
    },
    {
      readonly resolve: (
        credential: PasswordCredentialSnapshot,
      ) => Effect.Effect<Claims["Type"], PasswordUnavailable>;
    }
  >(`effect-auth/password/${moduleId}/Claims`);

  const Input = Schema.Struct({
    flowId: AuthenticationFlowId.check(Schema.isMaxLength(256)),
    ...PasswordSignInInput.fields,
  });

  const SignIn = makeOperation(`${moduleId}/sign-in`, {
    payload: Input,
    success: sessions.CompletionResult,
    error: Schema.Union([
      PasswordRejected,
      PasswordUnavailable,
      PasswordMethodUnsupported,
      HookDenied,
    ]),
    access: "any",
    exposure: "public",
    replay: "non-idempotent",
    credentials: true,
  });

  const handlersLayer = Layer.unwrap(
    Effect.gen(function* () {
      yield* Schema.decodeEffect(Schema.NonEmptyString.check(Schema.isMaxLength(128)))(
        moduleId,
      ).pipe(Effect.mapError(() => PasswordMethodConfigurationError.make({})));
      const configured = yield* policy;

      return SignIn.credentialHandlerLayer(
        Effect.fn("Passwords.signIn")(function* (request) {
          const { verifyPassword } = makePasswordVerification({ moduleId, policy: configured });
          const verified = yield* verifyPassword(request, "sign-in");

          const claims = yield* (yield* ClaimsForPassword).resolve(
            yield* snapshotPasswordCredential(verified.credential),
          );

          return yield* (yield* sessions.AuthenticationCompletion)
            .prepare({ evidence: verified.evidence, claims })
            .pipe(Effect.flatMap(readPasswordCommit), Effect.mapError(passwordCompletionFailure));
        }),
      );
    }),
  );

  const layer = handlersLayer.pipe(Layer.provide(hashingLayer), Layer.provide(cryptoLayer));

  return Object.freeze({
    persistence: { kind: "password" as const, moduleId, management: false as const },
    ClaimsForPassword,
    layer,
    handlersLayer,
    operations: { SignIn },
    group: operationGroup(SignIn),
    strategy: makeAuthStrategy(
      {
        signIn: Effect.fn("Passwords.signInRequest")(function* (
          invocation: AuthInvocation,
          request: Omit<typeof Input.Encoded, "flowId">,
        ) {
          const flowId = yield* (yield* Crypto.Crypto).randomUUIDv4.pipe(
            Effect.mapError(() => PasswordUnavailable.make({})),
          );

          return yield* SignIn.invoke(invocation, { ...request, flowId });
        }),
      },
      layer.pipe(Layer.provideMerge(cryptoLayer)),
      { completion: true },
    ),
  });
};
