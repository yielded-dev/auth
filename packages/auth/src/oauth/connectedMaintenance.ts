import * as Cause from "effect/Cause";
import * as Context from "effect/Context";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Exit from "effect/Exit";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";

import { prepareCommit, hasCommitScope } from "../hooks/commit";
import { reportAuthFailure } from "../internal/diagnostics";
import type { AuthInvocation } from "../operations/context";
import { OperationForbidden } from "../operations/errors";
import { makeOperation, operationGroup } from "../operations/operation";
import { CleanupResult } from "../persistence/cleanup";
import {
  captureConnectedPolicy,
  connectedBounded,
  connectedRead,
  reportConnectedFailure,
  validateConnectedPolicy,
} from "./connectedAccess";
import * as M from "./connectedModels";
import { wipeConnectedMaterial } from "./grantTokens";
import { OAuthConnectedPersistence } from "./OAuthConnectedPersistence";
import { OAuthConnectedProtocol } from "./OAuthConnectedProtocol";
import {
  OAuthConnectedRevocations,
  OAuthConnectedRevocationClaim,
  OAuthConnectedRevocationDecision,
} from "./OAuthConnectedRevocations";
import { OAuthConnectedTokenProtector } from "./OAuthConnectedTokenProtector";
import { OAuthMethodUnsupported, OAuthUnavailable } from "./signInErrors";
import { OAuthClaimId, OAuthCleanupInput } from "./signInModels";
import { makeOAuthSnapshot } from "./signInSnapshot";

const Failure = Schema.Union([OperationForbidden, OAuthMethodUnsupported, OAuthUnavailable]);
const RunResult = Schema.Struct({ outcome: Schema.Literals(["Empty", "Confirmed", "Unknown"]) });
const Cleanup = Schema.Struct({ limit: OAuthCleanupInput.fields.limit });

const authorize = Effect.fn("OAuthConnectedMaintenance.authorize")(function* (
  invocation: AuthInvocation,
) {
  if (yield* hasCommitScope) return yield* OAuthMethodUnsupported.make({});
  if (invocation._tag !== "System") return yield* OperationForbidden.make({});
});

export interface MaintenanceModule<Id extends string> {
  readonly moduleId: Id;
  readonly kind: "oauth-connected-maintenance";
}

/** Explicit privileged maintenance. No scheduler, retry loop or expired takeover. */
export const makeOAuthConnectedMaintenance = <const Id extends string>(
  moduleId: Id,
  configuration: M.OAuthConnectedPolicy,
) => {
  const ConnectedMaintenance = Context.Service<
    MaintenanceModule<Id>,
    {
      readonly cleanup: (
        invocation: AuthInvocation,
        limit: number,
      ) => Effect.Effect<CleanupResult, typeof Failure.Type>;
      readonly runRevocation: (
        invocation: AuthInvocation,
      ) => Effect.Effect<typeof RunResult.Type, typeof Failure.Type>;
    }
  >()("effect-auth/oauth/" + moduleId.length + ":" + moduleId + "/ConnectedMaintenance");

  const captured = captureConnectedPolicy(configuration);

  const maintenanceLayer = Layer.effect(
    ConnectedMaintenance,
    Effect.gen(function* () {
      const { id, policy } = yield* validateConnectedPolicy(moduleId, captured);
      const { cleanup: clean } = yield* OAuthConnectedPersistence;
      const revocations = yield* Effect.serviceOption(OAuthConnectedRevocations);
      const { revokeGrant, ready } = yield* OAuthConnectedProtocol;
      const { open } = yield* OAuthConnectedTokenProtector;
      const { randomBytes } = yield* SecureRandom.SecureRandom;

      const cleanup = Effect.fn("OAuthConnectedMaintenance.cleanup")(function* (
        invocation: AuthInvocation,
        limit: number,
      ) {
        yield* authorize(invocation);

        const input = yield* snapshotOAuthCleanupInput.effect({
          moduleId: id,
          limit,
        });

        const receipt = yield* clean(
          input,
          prepareCommit((value, journal) =>
            Result.gen(function* () {
              const result = snapshotCleanupResult.sync(value);

              if (result.removed > input.limit)
                return yield* Result.fail(OAuthUnavailable.make({}));

              return journal.prepare(result);
            }),
          ),
        );

        return yield* connectedRead(receipt);
      }, reportConnectedFailure);

      const runRevocation = Effect.fn("OAuthConnectedMaintenance.runRevocation")(function* (
        invocation: AuthInvocation,
      ) {
        yield* authorize(invocation);
        if (Option.isNone(revocations)) return yield* OAuthMethodUnsupported.make({});
        const { peek, claim, settle } = revocations.value;

        const bytes = yield* randomBytes(32).pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(Cause.map(cause, () => OAuthUnavailable.make({}))),
          ),
        );

        const claimId = OAuthClaimId.make(Base64Url.encode(bytes));

        bytes.fill(0);

        const runClaimed = (
          jobId: typeof M.OAuthConnectedRevocationJob.fields.jobId.Type | undefined,
        ) =>
          Effect.uninterruptibleMask((restore) =>
            Effect.gen(function* () {
              const receipt = yield* restore(
                claim(
                  {
                    moduleId: id,
                    claimId,
                    lifetimeMillis: policy.refreshClaimLifetimeMillis,
                    ...(jobId === undefined ? {} : { jobId }),
                  },
                  (value, journal) =>
                    journal.prepare(snapshotOAuthConnectedRevocationDecision.sync(value)),
                ),
              );

              const decision = yield* connectedRead(receipt);

              if (decision._tag === "Empty") {
                return jobId === undefined ? { outcome: "Empty" as const } : undefined;
              }
              const owned = yield* snapshotOAuthConnectedRevocationClaim.effect(decision.claim);

              if (
                owned.claimId !== claimId ||
                owned.job.grant.context.moduleId !== id ||
                owned.claimExpiresAtMillis !==
                  owned.claimedAtMillis + policy.refreshClaimLifetimeMillis ||
                owned.claimedAtMillis > DateTime.toEpochMillis(yield* DateTime.now)
              )
                return yield* OAuthUnavailable.make({});

              const call = Effect.gen(function* () {
                const context = owned.job.grant.context;

                if (
                  context.configuration.profile.revocation !== "provider" ||
                  DateTime.toEpochMillis(yield* DateTime.now) >= owned.claimExpiresAtMillis
                )
                  return yield* OAuthUnavailable.make({});

                const material = yield* open({
                  context: owned.job.grant.context,
                  sealed: owned.job.grant.sealed,
                }).pipe(
                  Effect.flatMap((value) => snapshotOAuthConnectedTokenMaterial.effect(value)),
                );

                return yield* Effect.gen(function* () {
                  return yield* revokeGrant({
                    context: yield* snapshotOAuthConnectedTokenContext.effect(context),
                    material: yield* snapshotOAuthConnectedTokenMaterial.effect(material),
                  }).pipe(
                    Effect.flatMap((value) =>
                      Schema.decodeEffect(Schema.Literal("Confirmed"))(value),
                    ),
                  );
                }).pipe(Effect.ensuring(Effect.sync(() => wipeConnectedMaterial(material))));
              });

              const result = yield* Effect.exit(
                restore(
                  connectedBounded(
                    call,
                    Math.max(
                      1,
                      owned.claimExpiresAtMillis - DateTime.toEpochMillis(yield* DateTime.now),
                    ),
                  ),
                ),
              );

              const outcome =
                Exit.isSuccess(result) &&
                DateTime.toEpochMillis(yield* DateTime.now) < owned.claimExpiresAtMillis
                  ? ("Confirmed" as const)
                  : ("Unknown" as const);

              // Request settlement cancellation after five seconds. Scoped driver
              // cleanup may take longer; an unknown outcome permits no retry.
              const final = yield* Effect.exit(
                connectedBounded(
                  settle({ claim: owned, outcome }, (value, journal) =>
                    journal.prepare(snapshotSettlement.sync(value)),
                  ).pipe(Effect.flatMap(connectedRead)),
                  5_000,
                ),
              );

              if (Exit.isFailure(final)) {
                const cause = Cause.map(final.cause, () => OAuthUnavailable.make({}));

                return yield* Effect.failCause(
                  Exit.isFailure(result)
                    ? Cause.combine(
                        Cause.map(result.cause, () => OAuthUnavailable.make({})),
                        cause,
                      )
                    : cause,
                );
              }

              if (Exit.isFailure(result)) {
                if (Cause.hasInterrupts(result.cause) || Cause.hasDies(result.cause))
                  return yield* Effect.failCause(
                    Cause.map(result.cause, () => OAuthUnavailable.make({})),
                  );

                yield* reportAuthFailure("oauth-connected", result.cause);
              }

              return { outcome: final.value.settled ? outcome : ("Unknown" as const) };
            }),
          );

        if (ready === undefined) {
          return (yield* runClaimed(undefined)) ?? { outcome: "Empty" as const };
        }

        if (peek === undefined) {
          return yield* OAuthUnavailable.make({});
        }

        // Bounded scan so one temporarily unready registration does not stall
        // healthy revocation jobs queued behind it.
        const excluded: Array<typeof M.OAuthConnectedRevocationJob.fields.jobId.Type> = [];
        const failedConfigs = new Set<string>();
        let sawUnavailable = false;

        for (let attempt = 0; attempt < 32; attempt++) {
          const pending = yield* peek({
            moduleId: id,
            ...(excluded.length === 0 ? {} : { excludeJobIds: excluded }),
          });

          if (pending === undefined) {
            return sawUnavailable
              ? yield* OAuthUnavailable.make({})
              : { outcome: "Empty" as const };
          }

          const config = pending.grant.context.configuration;

          const configKey = JSON.stringify([
            config.provider,
            config.configurationGeneration,
            config.issuer,
            config.callbackId,
            config.responseIssuerMode,
          ]);

          if (failedConfigs.has(configKey)) {
            sawUnavailable = true;
            excluded.push(pending.jobId);
            continue;
          }

          const readiness = yield* Effect.result(ready(config));

          if (readiness._tag === "Failure") {
            sawUnavailable = true;
            failedConfigs.add(configKey);
            excluded.push(pending.jobId);
            continue;
          }

          const outcome = yield* runClaimed(pending.jobId);

          if (outcome !== undefined) return outcome;
        }

        return sawUnavailable ? yield* OAuthUnavailable.make({}) : { outcome: "Empty" as const };
      });

      return ConnectedMaintenance.of({
        cleanup,
        runRevocation: (invocation) => runRevocation(invocation).pipe(reportConnectedFailure),
      });
    }),
  );

  const CleanupOperation = makeOperation(`${moduleId}/connected/maintenance/cleanup`, {
    payload: Cleanup,
    success: CleanupResult,
    error: Failure,
    access: "system",
    exposure: "internal",
    replay: "idempotent",
  });

  const RunRevocation = makeOperation(`${moduleId}/connected/maintenance/revocation`, {
    payload: Schema.Struct({}),
    success: RunResult,
    error: Failure,
    access: "system",
    exposure: "internal",
    replay: "non-idempotent",
  });

  const maintenanceHandlersLayer = Layer.mergeAll(
    CleanupOperation.handlerLayer(
      Effect.fn("OAuthConnected.Cleanup")(function* (input, invocation) {
        return yield* (yield* ConnectedMaintenance).cleanup(invocation, input.limit);
      }),
    ),
    RunRevocation.handlerLayer(
      Effect.fn("OAuthConnected.RunRevocation")(function* (_input, invocation) {
        return yield* (yield* ConnectedMaintenance).runRevocation(invocation);
      }),
    ),
  );

  return {
    ConnectedMaintenance,
    maintenanceLayer,
    maintenanceHandlersLayer,
    maintenanceOperations: Object.freeze({ Cleanup: CleanupOperation, RunRevocation }),
    maintenanceGroup: operationGroup(CleanupOperation, RunRevocation),
  };
};

const snapshotOAuthCleanupInput = makeOAuthSnapshot(OAuthCleanupInput);
const snapshotCleanupResult = makeOAuthSnapshot(CleanupResult);

const snapshotOAuthConnectedRevocationDecision = makeOAuthSnapshot(
  OAuthConnectedRevocationDecision,
);

const snapshotOAuthConnectedRevocationClaim = makeOAuthSnapshot(OAuthConnectedRevocationClaim);
const snapshotOAuthConnectedTokenMaterial = makeOAuthSnapshot(M.OAuthConnectedTokenMaterial);
const snapshotOAuthConnectedTokenContext = makeOAuthSnapshot(M.OAuthConnectedTokenContext);

const snapshotSettlement = makeOAuthSnapshot(Schema.Struct({ settled: Schema.Boolean }));
