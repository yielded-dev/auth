import { Context, DateTime, Effect, Layer, Schema, type Types } from "effect";

import { makeAuthStrategy } from "../auth/AuthStrategy";
import { cryptoLayer, defaultLayer, hooksLayer } from "../auth/defaults";
import type { AuthInvocation } from "../operations/context";
import type { AuthOperationResult } from "../operations/credentials";
import { operationGroup } from "../operations/operation";
import { make as makePasskeyContract } from "../PasskeyContract";
import type { AuthenticationAuthority } from "../sessions/AuthenticationAuthority";
import type { makeSessionModule } from "../sessions/module";
import {
  makePasskeyActions,
  capturePasskeyPolicy,
  passkeyUnexpected,
  makePasskeyCeremony,
  passkeyNoAmbient,
  readPasskeyCommit,
} from "./actions";
import type { PasskeyFailure } from "./errors";
import {
  PasskeyMethodUnsupported,
  PasskeyRejected,
  PasskeyUnavailable,
  PasskeyConfigurationError,
} from "./errors";
import { makePasskeyManagement } from "./management";
import {
  type PasskeyAuthenticationStarted,
  type PasskeyCleanupResult,
  PasskeyBegin,
  PasskeyComplete,
  type PasskeyCredential,
} from "./models";
import type { PasskeyCredentials } from "./PasskeyCredentials";
import { PasskeyPersistence } from "./PasskeyPersistence";
import { makePasskeyPending } from "./pending";
import { type PasskeyManagementPolicy, PasskeyMethodPolicy, validatePasskeyPolicy } from "./policy";
import { makePasskeyRegistration } from "./registration";
import { snapshotPasskey } from "./snapshot";
import { makePasskeyStepUp } from "./stepUp";

type PasskeyConfiguration =
  | { readonly policy: PasskeyMethodPolicy; readonly relyingParty?: never }
  | {
      readonly policy?: never;
      readonly relyingParty: {
        readonly id: string;
        readonly name: string;
        readonly origins: readonly string[];
        readonly developmentLocalhost?: boolean;
      };
    };

/** Descriptors capture policy data once; invalid policies remain typed Effect failures. */
export const capturePasskeyConfiguration = (options: PasskeyConfiguration) => {
  const defaultPolicy =
    options.policy === undefined
      ? {
          generation: 1,
          lifetimeMillis: 300_000,
          claimLifetimeMillis: 30_000,
          retentionMillis: 3_600_000,
          maximumPending: 1000,
          maximumPendingPerSubject: 5,
          admission: {
            global: { limit: 1000, windowMillis: 60_000 },
            subject: { limit: 10, windowMillis: 60_000 },
            target: { limit: 10, windowMillis: 60_000 },
          },
          profiles: [
            {
              profileId: "default",
              generation: 1,
              rpId: options.relyingParty?.id,
              rpName: options.relyingParty?.name,
              origins: Array.isArray(options.relyingParty?.origins)
                ? [...options.relyingParty.origins]
                : options.relyingParty?.origins,
              developmentLocalhost: options.relyingParty?.developmentLocalhost ?? false,
              residentKey: "required",
              userVerification: "required",
              primarySignIn: true,
              attestation: "none",
              algorithms: [-7, -257],
            },
          ],
        }
      : undefined;

  return options.policy === undefined
    ? // eslint-disable-next-line no-restricted-properties -- Relying-party configuration becomes a complete, validated policy here.
      Schema.decodeUnknownEffect(PasskeyMethodPolicy)(defaultPolicy).pipe(
        Effect.flatMap(validatePasskeyPolicy),
        Effect.mapError(() => PasskeyConfigurationError.make({})),
      )
    : capturePasskeyPolicy(options.policy);
};

export const makePasskeyMethod = <
  const Id extends string,
  const SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
>(
  moduleId: Id,
  options: {
    readonly sessions: ReturnType<typeof makeSessionModule<SessionId, Claims>>;
  } & PasskeyConfiguration,
  configuredSource?: ReturnType<typeof capturePasskeyConfiguration>,
) => {
  const sessions = options.sessions;
  const source = configuredSource ?? capturePasskeyConfiguration(options);
  const ceremony = makePasskeyCeremony(moduleId, source, "sign-in");

  const ClaimsForPasskey = Context.Service<
    {
      readonly moduleId: Id;
      readonly kind: "passkey-claims";
      readonly claims: Types.Invariant<Claims["Type"]>;
    },
    {
      readonly resolve: (
        credential: PasskeyCredential,
      ) => Effect.Effect<Claims["Type"], PasskeyUnavailable>;
    }
  >(`effect-auth/ClaimsForPasskey/${moduleId.length}:${moduleId}`);

  const Passkeys = Context.Service<
    {
      readonly moduleId: Id;
      readonly kind: "passkeys";
      readonly claims: Types.Invariant<Claims["Type"]>;
    },
    {
      readonly begin: (
        invocation: AuthInvocation,
        input: PasskeyBegin,
      ) => Effect.Effect<AuthOperationResult<PasskeyAuthenticationStarted>, PasskeyFailure>;
      readonly complete: (
        invocation: AuthInvocation,
        input: PasskeyComplete,
      ) => Effect.Effect<
        AuthOperationResult<typeof sessions.CompletionResult.Type>,
        PasskeyFailure
      >;
      readonly cleanup: (
        invocation: AuthInvocation,
        limit: number,
      ) => Effect.Effect<PasskeyCleanupResult, PasskeyFailure>;
    }
  >(`effect-auth/Passkeys/${moduleId.length}:${moduleId}`);

  const layer = Layer.effect(
    Passkeys,
    Effect.gen(function* () {
      const runtime = yield* ceremony.make,
        claims = yield* ClaimsForPasskey,
        completion = yield* sessions.AuthenticationCompletion,
        persistence = yield* PasskeyPersistence;

      const services = yield* Effect.context<
        | PasskeyCredentials
        | AuthenticationAuthority
        | Claims["EncodingServices"]
        | Claims["DecodingServices"]
      >();

      const claimsCodec = Schema.toCodecJson(Schema.toType(sessions.claims));

      return Passkeys.of({
        begin: Effect.fn("Passkeys.begin")(function* (invocation, input) {
          input = yield* snapshotPasskey(Schema.toType(PasskeyBegin), input);
          yield* passkeyNoAmbient();
          if (invocation._tag !== "Guest") return yield* PasskeyRejected.make({});

          return yield* runtime.beginAuthentication(input, { _tag: "SignIn" });
        }, passkeyUnexpected),
        complete: Effect.fn("Passkeys.complete")(function* (invocation, input) {
          input = yield* snapshotPasskey(Schema.toType(PasskeyComplete), input);
          yield* passkeyNoAmbient();
          if (invocation._tag !== "Guest") return yield* PasskeyRejected.make({});

          const verified = yield* runtime
            .authentication(input, { _tag: "SignIn" })
            .pipe(Effect.provide(services));

          const resolved = yield* claims.resolve(verified.credential);

          const encoded = yield* Schema.encodeEffect(claimsCodec)(resolved).pipe(
            Effect.provide(services),
            Effect.mapError(() => PasskeyUnavailable.make({})),
          );

          const captured = yield* Schema.decodeEffect(claimsCodec)(encoded).pipe(
            Effect.provide(services),
            Effect.mapError(() => PasskeyUnavailable.make({})),
          );

          const result = yield* readPasskeyCommit(
            yield* completion
              .prepare({ evidence: verified.evidence, claims: captured })
              .pipe(
                Effect.mapError((error) =>
                  error._tag === "HookDenied"
                    ? error
                    : error._tag === "SessionUnavailable"
                      ? PasskeyUnavailable.make({})
                      : error._tag === "SessionCapabilityUnsupported"
                        ? PasskeyMethodUnsupported.make({})
                        : PasskeyRejected.make({}),
                ),
              ),
          );

          return {
            value: result.value,
            credentialCommands: [...verified.credentialCommands, ...result.credentialCommands],
          };
        }, passkeyUnexpected),
        cleanup: Effect.fn("Passkeys.cleanup")(function* (invocation, limit) {
          yield* passkeyNoAmbient();
          if (invocation._tag !== "System") return yield* PasskeyMethodUnsupported.make({});
          yield* Schema.decodeEffect(
            Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 1000 })),
          )(limit).pipe(Effect.mapError(() => PasskeyRejected.make({})));

          return yield* readPasskeyCommit(
            yield* persistence.cleanup(
              { moduleId, nowMillis: DateTime.toEpochMillis(yield* DateTime.now), limit },
              (value, journal) => journal.prepare(value),
            ),
          );
        }, passkeyUnexpected),
      });
    }),
  );

  const { Begin, Complete, Cleanup } = makePasskeyContract(moduleId, sessions).operations;

  const handlersLayer = Layer.mergeAll(
    Begin.credentialHandlerLayer((input, invocation) =>
      Effect.flatMap(Passkeys, (service) => service.begin(invocation, input)),
    ),
    Complete.credentialHandlerLayer((input, invocation) =>
      Effect.flatMap(Passkeys, (service) => service.complete(invocation, input)),
    ),
    Cleanup.handlerLayer((input, invocation) =>
      Effect.flatMap(Passkeys, (service) => service.cleanup(invocation, input.limit)),
    ),
  );

  const actions = makePasskeyActions(moduleId, source);

  // Protocol verification is an explicit server capability. Keeping it out of
  // this shared contract avoids bundling the maintained verifier into clients.
  const strategyLayer = handlersLayer.pipe(
    Layer.provide(defaultLayer(Passkeys, layer)),
    Layer.provide(defaultLayer(ceremony.binding.RequestBinding, ceremony.binding.layer)),
    Layer.provide(hooksLayer),
    Layer.provide(cryptoLayer),
  );

  const registration = <Registration extends Schema.Codec<unknown, unknown, unknown, unknown>>(
    codec: Registration,
  ) => {
    const module = makePasskeyRegistration(moduleId, source, codec);

    return Object.freeze({
      ...module,
      strategy: makeAuthStrategy(
        {
          register: module.operations.Begin.invoke,
          completeRegistration: module.operations.Complete.invoke,
        },
        module.handlersLayer.pipe(
          Layer.provide(defaultLayer(module.Registrations, module.layer)),
          Layer.provide(defaultLayer(module.binding.RequestBinding, module.binding.layer)),
          Layer.provide(hooksLayer),
          Layer.provide(cryptoLayer),
        ),
      ),
    });
  };

  const management = (policy: PasskeyManagementPolicy) => {
    const module = makePasskeyManagement(moduleId, source, policy, sessions);

    return Object.freeze({
      ...module,
      strategy: makeAuthStrategy(
        {
          enrollPasskey: module.operations.Begin.invoke,
          completePasskeyEnrollment: module.operations.Complete.invoke,
          listPasskeys: module.operations.List.invoke,
          renamePasskey: module.operations.Rename.invoke,
          removePasskey: module.operations.Remove.invoke,
        },
        module.handlersLayer.pipe(
          Layer.provide(defaultLayer(module.Management, module.layer)),
          Layer.provide(defaultLayer(module.binding.RequestBinding, module.binding.layer)),
          Layer.provide(hooksLayer),
          Layer.provide(cryptoLayer),
        ),
      ),
    });
  };

  const pendingModule = makePasskeyPending(moduleId, source, sessions);

  const pending = Object.freeze({
    ...pendingModule,
    strategy: makeAuthStrategy(
      {
        beginPending: pendingModule.operations.Begin.invoke,
        completePending: pendingModule.operations.Complete.invoke,
      },
      pendingModule.handlersLayer.pipe(
        Layer.provide(defaultLayer(pendingModule.Pending, pendingModule.layer)),
        Layer.provide(
          defaultLayer(pendingModule.binding.RequestBinding, pendingModule.binding.layer),
        ),
        Layer.provide(hooksLayer),
        Layer.provide(cryptoLayer),
      ),
      { completion: true },
    ),
  });

  const stepUpModule = makePasskeyStepUp(moduleId, source, sessions);

  const stepUp = Object.freeze({
    ...stepUpModule,
    strategy: makeAuthStrategy(
      {
        beginStepUp: stepUpModule.operations.Begin.invoke,
        completeStepUp: stepUpModule.operations.Complete.invoke,
      },
      stepUpModule.handlersLayer.pipe(
        Layer.provide(defaultLayer(stepUpModule.StepUp, stepUpModule.layer)),
        Layer.provide(
          defaultLayer(stepUpModule.binding.RequestBinding, stepUpModule.binding.layer),
        ),
        Layer.provide(hooksLayer),
        Layer.provide(cryptoLayer),
      ),
    ),
  });

  return Object.freeze({
    strategy: makeAuthStrategy(
      { signIn: Begin.invoke, completeSignIn: Complete.invoke },
      strategyLayer,
      { completion: true },
    ),
    Passkeys,
    ClaimsForPasskey,
    binding: ceremony.binding,
    layer,
    handlersLayer,
    operations: Object.freeze({ Begin, Complete, Cleanup }),
    group: operationGroup(Begin, Complete, Cleanup),
    registration,
    management,
    pending,
    stepUp,
    actions,
  });
};
