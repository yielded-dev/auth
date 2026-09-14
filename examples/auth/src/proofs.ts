import { BunRuntime } from "@effect/platform-bun";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import {
  type AuthCredentialCommand,
  AuthCredentialCommandCollector,
} from "@yielded/auth/Operations";
import {
  ProofKeys,
  EmailProofDelivery,
  IdentifierProofBinding,
  make as makeProofs,
  ProofPurpose,
  ProofRequestId,
  SmsProofDelivery,
  type ProofDeliveryMessage,
  type ProofPolicy,
} from "@yielded/auth/Proofs";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { Effect, Encoding, Layer, Redacted } from "effect";

import { makeExampleProofAuthority } from "./proof-consumer";

const budget = { limit: 20, windowMillis: 60_000 };

const policy: ProofPolicy = {
  lifetimeMillis: 60_000,
  continuationLifetimeMillis: 30_000,
  maximumFailedAttempts: 3,
  maximumDeliveryAttempts: 1,
  deliveryClaimMillis: 5_000,
  deliveryRetryMillis: 10_000,
  requestRetentionMillis: 120_000,
  abuse: {
    issues: budget,
    attempts: budget,
    subjectIssues: budget,
    subjectAttempts: budget,
    actionIssues: budget,
    actionAttempts: budget,
    resendCooldownMillis: 0,
  },
};

const base = Layer.mergeAll(
  layerWebCrypto,
  LifecycleHooks.empty,
  ProofKeys.layer({
    activeKeyId: "current",
    keys: [
      {
        id: "current",
        material: Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32).fill(23))),
      },
    ],
  }),
);

const authority = Layer.unwrap(makeExampleProofAuthority).pipe(Layer.provide(base));
// Trusted method authority resolves eligibility/binding. An HTTP client never supplies it.
const invocation = { _tag: "System", authority: "example-method" } as const;

const program = Effect.gen(function* () {
  for (const channel of ["email", "sms"] as const) {
    const delivered: ProofDeliveryMessage[] = [];
    const commands: AuthCredentialCommand[] = [];

    const sender = (message: ProofDeliveryMessage) =>
      Effect.sync(() => {
        delivered.push(message);

        return { _tag: "Accepted" as const };
      });

    const vendor = { vendorId: `example-${channel}`, idempotencyMillis: 0 };

    const proofs = makeProofs({
      namespace: `example/${channel}`,
      purpose: ProofPurpose.make(`${channel}-verification`),
      binding: IdentifierProofBinding,
      channel,
      template: "verify-identifier",
      secret: channel === "email" ? { _tag: "NumericCode", digits: 6 } : { _tag: "Token" },
      policy,
    });

    const capability = (
      channel === "email"
        ? proofs.emailLayer.pipe(Layer.provide(EmailProofDelivery.layer(vendor, sender)))
        : proofs.smsLayer.pipe(Layer.provide(SmsProofDelivery.layer(vendor, sender)))
    ).pipe(Layer.provide(authority), Layer.provide(base));

    const handlers = proofs.handlersLayer.pipe(Layer.provide(capability));

    const binding = {
      _tag: "Identifier",
      flowId: `${channel}-flow`,
      contextDigest: "example-action-and-replacement-fingerprint",
      identifier: {
        namespace: channel,
        value: channel === "email" ? "reader@example.invalid" : "+15555550123",
      },
    } as const;

    const call = {
      credentialCommandSink: (batch: ReadonlyArray<AuthCredentialCommand>) =>
        Effect.sync(() => {
          commands.push(...batch);
        }),
    };

    yield* Effect.gen(function* () {
      const receipt = yield* proofs.operations.Request.invoke(invocation, {
        requestId: ProofRequestId.make(`${channel}-request`),
        binding,
        locale: "en-ZA",
        eligible: true,
      });

      const duplicate = yield* proofs.operations.Request.invoke(invocation, {
        requestId: ProofRequestId.make(`${channel}-request`),
        binding,
        locale: "en-ZA",
        eligible: true,
      });

      if (duplicate.reference.proofId !== receipt.reference.proofId || delivered.length !== 1)
        return yield* Effect.die(
          "request replay must retain the original reference without sending again",
        );

      const resent = yield* proofs.operations.Resend.invoke(invocation, {
        requestId: ProofRequestId.make(`${channel}-resend`),
        supersedes: receipt.reference.proofId,
        binding,
        locale: "en-ZA",
        eligible: true,
      });

      const first = delivered[0];
      const latest = delivered[1];

      if (!first || !latest) return yield* Effect.die("example delivery missing");

      const superseded = yield* proofs.operations.Attempt.invoke(invocation, {
        reference: receipt.reference,
        binding,
        credential: Redacted.value(first.secret),
      }).pipe(
        Effect.provideService(AuthCredentialCommandCollector, call.credentialCommandSink),
        Effect.result,
      );

      if (superseded._tag !== "Failure") return yield* Effect.die("superseded proof accepted");

      const accepted = yield* proofs.operations.Attempt.invoke(invocation, {
        reference: resent.reference,
        binding,
        credential: Redacted.value(latest.secret),
      }).pipe(Effect.provideService(AuthCredentialCommandCollector, call.credentialCommandSink));

      const issued = commands.find(
        (command) => command._tag === "Issue" && command.slot === "proof-continuation",
      );

      if (issued?._tag !== "Issue") return yield* Effect.die("private continuation missing");
      // This standalone completion deliberately has burn-on-downstream-failure semantics.
      // Password reset/linking instead use Proofs.planComplete in one atomic method command.
      yield* proofs.operations.Complete.invoke(invocation, {
        continuationId: accepted.continuation.continuationId,
        binding,
        credential: Redacted.value(issued.credential),
      }).pipe(Effect.provideService(AuthCredentialCommandCollector, call.credentialCommandSink));

      const replay = yield* proofs.operations.Complete.invoke(invocation, {
        continuationId: accepted.continuation.continuationId,
        binding,
        credential: Redacted.value(issued.credential),
      }).pipe(
        Effect.provideService(AuthCredentialCommandCollector, call.credentialCommandSink),
        Effect.result,
      );

      if (replay._tag !== "Failure") return yield* Effect.die("continuation replay accepted");
      yield* Effect.log(
        `${channel}: duplicate suppressed, resend superseded, private continuation consumed once`,
      );
    }).pipe(Effect.provide(handlers));
  }
});

BunRuntime.runMain(program);
