import { BunRuntime } from "@effect/platform-bun";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { phonePersistenceLayer } from "@yielded/auth-persistence/drizzle";
import {
  makeAuthenticationAuthorityServices,
  makePhonePersistenceServices,
  makeProofPersistenceServices,
} from "@yielded/auth-persistence/drizzle/sqlite-bun";
import { AuthRequest, RequestBindingConfig } from "@yielded/auth/Auth";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import { guest, type AuthCredentialCommand, type AuthInvocation } from "@yielded/auth/Operations";
import {
  PhoneActionEvidence,
  PhoneActionRequired,
  PhoneDeliveryEligibility,
  PhoneOtpUnavailable,
  PhoneRequestContext,
} from "@yielded/auth/PhoneOtp";
import { ProofPersistence, ProofKeys } from "@yielded/auth/Proofs";
import { AuthenticationAuthority } from "@yielded/auth/Sessions";
import { SmsDelivery, type SmsMessage } from "@yielded/auth/SmsDelivery";
import { PhoneOtp } from "@yielded/auth/strategies";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { eq } from "drizzle-orm";
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Effect, Layer, Redacted } from "effect";

import { keyring, phone, sessionPolicy, sessions, shopAuth } from "./phone-application";
import {
  customer,
  credential,
  identifier,
  mapping,
  migrate,
  nativeSubject,
  proofs,
  requirement,
  subjectId,
} from "./phone-sqlite-schema";

const assert: (condition: unknown, message: string) => asserts condition = (condition, message) => {
  if (!condition) throw new Error(message);
};

export const phoneConsumer = Effect.gen(function* () {
  const client = yield* SqliteClient.SqliteClient,
    database = yield* Drizzle.makeWithDefaults({});

  yield* migrate(client);

  const phoneStorage = phonePersistenceLayer(makePhonePersistenceServices(database, mapping));
  const proofServices = yield* makeProofPersistenceServices(database, proofs);

  const authority = yield* makeAuthenticationAuthorityServices(database, {
    subjectId,
    subject: {
      table: customer,
      id: "customerNo",
      status: "enabled",
      securityRevision: "security",
      isActiveStatus: (value) => value === true,
      decodeRequirement: () => Effect.succeed(requirement),
    },
    credential: {
      table: credential,
      subjectId: "customerNo",
      credentialId: "key",
      revision: "revision",
      status: "enabled",
      isActiveStatus: (value) => value === true,
    },
    isConstraintConflict: () => false,
  });

  const sent: SmsMessage[] = [];
  let failNext = false;

  const sender = Layer.succeed(SmsDelivery, {
    send: (message) =>
      Effect.sync(() => {
        if (failNext) {
          failNext = false;

          return { _tag: "DefiniteFailure" as const, reason: "unavailable" as const };
        }
        sent.push(message);

        return { _tag: "Accepted" as const };
      }),
  });

  const base = Layer.mergeAll(
    layerWebCrypto,
    LifecycleHooks.empty,
    RequestBindingConfig.layer({ keyring, lifetimeMillis: 120_000, generation: 1 }),
    sender,
    ProofKeys.layer(keyring),
    PhoneOtp.Template.layer({ render: (code) => code }),
    Layer.succeed(PhoneDeliveryEligibility, {
      allowed: (number) => Effect.succeed(number.startsWith("+2782")),
    }),
  );

  const ports = Layer.mergeAll(
    phoneStorage,
    Layer.succeed(ProofPersistence, proofServices.proofPersistence),
    Layer.succeed(AuthenticationAuthority, authority.authenticationAuthority),
    Layer.succeed(phone.ClaimsForPhone, {
      resolve: (snapshot) =>
        database
          .select()
          .from(customer)
          .where(eq(customer.customerNo, nativeSubject(snapshot.revision.subjectId)))
          .pipe(
            Effect.flatMap((rows) =>
              rows[0] === undefined
                ? Effect.fail(PhoneOtpUnavailable.make({}))
                : Effect.succeed({
                    customerNumber: rows[0].customerNo,
                    segment:
                      rows[0].segment === "wholesale"
                        ? ("wholesale" as const)
                        : ("retail" as const),
                  }),
            ),
            Effect.mapError(() => PhoneOtpUnavailable.make({})),
          ),
    }),
  );

  const strategy = sessions.statelessLayer(sessionPolicy, keyring).pipe(Layer.provide(base));

  const completion = sessions
    .completionLayer()
    .pipe(Layer.provide(Layer.mergeAll(ports, strategy)), Layer.provide(base));

  const actionEvidence = Layer.effect(
    PhoneActionEvidence,
    Effect.map(sessions.SessionStrategy, (strategy) => ({
      verify: ({ invocation, challenge, proof }) =>
        Effect.gen(function* () {
          if (invocation._tag !== "Authenticated" || proof === undefined)
            return yield* PhoneActionRequired.make({});

          const inspected = yield* strategy
            .inspect(proof)
            .pipe(Effect.mapError(() => PhoneActionRequired.make({})));

          if (inspected.provenance.evidence.revision.subjectId !== invocation.subjectId)
            return yield* PhoneActionRequired.make({});

          const evidence = {
            ...inspected.provenance.evidence,
            flowId: challenge.flowId,
            bindingDigest: challenge.bindingDigest,
          };

          const current = yield* authority.authenticationAuthority
            .requirements(evidence)
            .pipe(Effect.mapError(() => PhoneActionRequired.make({})));

          return { evidence, requirement: current };
        }),
    })),
  ).pipe(Layer.provide(strategy));

  const dependencies = Layer.mergeAll(ports, strategy, completion, actionEvidence, base);

  return yield* Effect.gen(function* () {
    const auth = yield* shopAuth.make,
      sessionStrategy = yield* sessions.SessionStrategy;

    const commands: AuthCredentialCommand[] = [];

    const collect = (items: ReadonlyArray<AuthCredentialCommand>) =>
      Effect.sync(() => {
        commands.push(...items);
      });

    const as = <A, E, R>(invocation: AuthInvocation, effect: Effect.Effect<A, E, R>) =>
      effect.pipe(
        Effect.provideService(AuthRequest, {
          invocation,
          credentials: {},
          credentialCommandSink: collect,
        }),
        Effect.provideService(PhoneRequestContext, {
          networkKey: Redacted.make("trusted-gateway/network-a"),
        }),
      );

    const token = (slot: "request-binding" | "session") => {
      const found = [...commands].reverse().find((c) => c._tag === "Issue" && c.slot === slot);

      if (found?._tag !== "Issue") throw new Error("missing private credential");

      return Redacted.value(found.credential);
    };

    const begin = (
      action: "register" | "verify" | "change",
      number: string,
      invocation: AuthInvocation,
      sourcePhoneNumber?: string,
    ) =>
      Effect.gen(function* () {
        const input = {
          action,
          flowId: crypto.randomUUID(),
          requestId: crypto.randomUUID(),
          commandId: crypto.randomUUID(),
          phoneNumber: number,
          locale: "en-ZA",
          ...(sourcePhoneNumber === undefined ? {} : { sourcePhoneNumber }),
        };

        const challenge = yield* as(invocation, auth.begin(input));

        return { input, challenge, binding: token("request-binding") };
      });

    const complete = (
      started: Effect.Success<ReturnType<typeof begin>>,
      invocation: AuthInvocation,
      actionProof?: string,
    ) =>
      Effect.gen(function* () {
        const message = sent.find((m) => m.id === started.challenge.reference.proofId);

        assert(message !== undefined, "controlled sender missed challenge");

        return yield* as(
          invocation,
          auth.completeLifecycle({
            ...started.input,
            requestBinding: started.binding,
            reference: started.challenge.reference,
            code: Redacted.value(message.body),
            ...(actionProof === undefined ? {} : { actionProof }),
          }),
        );
      });

    let registered = yield* begin("register", "+27820000001", guest);

    const wrong = yield* as(
      guest,
      auth.completeLifecycle({
        ...registered.input,
        requestBinding: registered.binding,
        reference: registered.challenge.reference,
        code:
          Redacted.value(
            sent.find((m) => m.id === registered.challenge.reference.proofId)!.body,
          ) === "000000"
            ? "111111"
            : "000000",
      }),
    ).pipe(Effect.result);

    assert(wrong._tag === "Failure", "wrong code accepted");

    const resendInput = {
      ...registered.input,
      requestId: crypto.randomUUID(),
      requestBinding: registered.binding,
      reference: registered.challenge.reference,
    };

    const resent = yield* as(guest, auth.resend(resendInput));
    const delivered = sent.length;
    const duplicateResend = yield* as(guest, auth.resend(resendInput));

    assert(
      duplicateResend.reference.proofId === resent.reference.proofId && sent.length === delivered,
      "resend retry duplicated SMS",
    );
    const superseded = yield* complete(registered, guest).pipe(Effect.result);

    assert(superseded._tag === "Failure", "superseded code accepted");
    registered = {
      ...registered,
      input: { ...registered.input, requestId: resendInput.requestId },
      challenge: resent,
    };
    const registration = yield* complete(registered, guest);

    assert(
      registration._tag === "Registered" && registration.completion._tag === "Authenticated",
      "phone registration failed",
    );

    const initialToken = token("session"),
      initial = yield* sessionStrategy.verify(Redacted.make(initialToken));

    assert(
      initial.claims.customerNumber === nativeSubject(initial.subjectId),
      "custom numeric claim mapping lost",
    );

    const caller = {
      _tag: "Authenticated" as const,
      subjectId: initial.subjectId,
      sessionId: initial.sessionId,
      assurance: initial.assurance,
    };

    const replay = yield* complete(registered, guest).pipe(Effect.result);

    assert(replay._tag === "Failure", "registration replay accepted");
    const verify = yield* begin("verify", "+27820000002", caller);
    const verified = yield* complete(verify, caller, initialToken);

    assert(
      verified._tag === "Updated" &&
        verified.invalidation.existingSessions === "original-absolute-expiry",
      "verification invalidation mismatch",
    );

    const signIn = Effect.fn("PhoneConsumer.signIn")(function* (number: string) {
      const challenge = yield* as(guest, auth.signIn({ phoneNumber: number, locale: "en-ZA" }));

      const requestBinding = token("request-binding"),
        message = sent.find((m) => m.id === challenge.reference.proofId);

      assert(message !== undefined, "sign-in was not delivered");

      const result = yield* as(
        guest,
        auth.completeSignIn({
          flowId: challenge.flowId,
          phoneNumber: number,
          requestBinding,
          reference: challenge.reference,
          code: Redacted.value(message.body),
        }),
      );

      assert(result._tag === "Authenticated", "phone-only sign-in failed");
      const signed = token("session");

      return { signed, session: yield* sessionStrategy.verify(Redacted.make(signed)) };
    });

    const verifiedLogin = yield* signIn("+27820000002"),
      freshCaller = {
        _tag: "Authenticated" as const,
        subjectId: verifiedLogin.session.subjectId,
        sessionId: verifiedLogin.session.sessionId,
        assurance: verifiedLogin.session.assurance,
      };

    const change = yield* begin("change", "+27820000003", freshCaller, "+27820000002");
    const changed = yield* complete(change, freshCaller, verifiedLogin.signed);

    assert(changed._tag === "Updated", "authenticated change failed");
    const after = yield* signIn("+27820000003");

    assert(after.session.subjectId === initial.subjectId, "change changed customer identity");
    const beforeConflict = sent.length;

    yield* begin("register", "+27820000002", guest);
    assert(sent.length === beforeConflict, "retired number was silently relinked");
    failNext = true;
    const failed = yield* begin("register", "+27820000004", guest);

    assert(
      !sent.some((m) => m.id === failed.challenge.reference.proofId),
      "failed delivery created accepted message",
    );
    const old = yield* sessionStrategy.verify(Redacted.make(initialToken));

    assert(
      old.absoluteExpiresAt.epochMilliseconds === initial.absoluteExpiresAt.epochMilliseconds,
      "pure-stateless old session lifetime changed",
    );
    const rows = yield* database.select().from(identifier);

    assert(
      rows.some((r) => r.value === "+27820000002" && !r.enabled),
      "source number still active",
    );
    const customers = yield* database.select().from(customer);

    assert(customers.length === 1, "conflict/failure provisioned customers");

    return {
      consumer: "numeric-customer/ISO-instants/custom-claims",
      registration: "verified",
      verification: "verified",
      change: "same-customer",
      signIn: "phone-only",
      wrongCode: "rejected",
      resend: "single-delivery/superseded-code-rejected",
      replay: "rejected",
      retiredNumber: "reserved",
      deliveryFailure: "contained",
      sessionMode: "pure-stateless-no-session-table",
      invalidation: "original-absolute-expiry",
    };
  }).pipe(Effect.provide(dependencies));
});

phoneConsumer.pipe(
  Effect.tap(Effect.log),
  Effect.provide(
    Layer.mergeAll(
      SqliteClient.layer({ filename: ":memory:" }),
      LifecycleHooks.empty,
      layerWebCrypto,
    ),
  ),
  Effect.scoped,
  BunRuntime.runMain,
);
