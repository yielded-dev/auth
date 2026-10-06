import * as M from "@yielded/auth/OAuth";
import {
  OAuthConnectedPersistence,
  OAuthConnectedRevocations,
  OAuthConnectedRevocationDecision,
  OAuthExternalIdentity,
  snapshotOAuthSync,
  type PrepareOAuthCommit,
  type OAuthUnavailable,
} from "@yielded/auth/OAuth";
/* oxlint-disable no-explicit-any -- concrete adapters retain the native database, table and ID types. */
import { type Crypto, Effect, Layer, type PlatformError, Schema } from "effect";
import type { Statement } from "effect/sql/Statement";

import type { PersistenceMappingError } from "../models/common";
import type { makeOAuthConnectedAccessKernel } from "./connected-access";
import type { makeOAuthConnectedFlowKernel } from "./connected-flow";
import { connectedInputs, connectedRevocationInputs } from "./connected-input";
import type { makeOAuthConnectedMaintenanceKernel } from "./connected-maintenance";
import type { makeOAuthConnectedManagementKernel } from "./connected-management";
import type { makeOAuthConnectedSettlementKernel } from "./connected-settlement";
import type { makeOAuthConnectedSignInKernel } from "./connected-sign-in";
import type * as STypes from "./connected-state";
import type { makeOAuthConnectedStateKernel } from "./connected-state";
import { capturedOAuthService } from "./input";
import { CurrentOAuthTransaction } from "./owner";
import { captureOAuthMapping } from "./state";
import type { OAuthExecution, OAuthTargetConfiguration, makeOAuthTargetKernel } from "./target";

export const makeOAuthConnectedTargetKernel = (
  A: ReturnType<typeof makeOAuthConnectedAccessKernel>,
  F: ReturnType<typeof makeOAuthConnectedFlowKernel>,
  Maintenance: ReturnType<typeof makeOAuthConnectedMaintenanceKernel>,
  Management: ReturnType<typeof makeOAuthConnectedManagementKernel>,
  connectedSettlement: Pick<ReturnType<typeof makeOAuthConnectedSettlementKernel>, "settle">,
  SignIn: ReturnType<typeof makeOAuthConnectedSignInKernel>,
  S: ReturnType<typeof makeOAuthConnectedStateKernel>,
  target: Pick<
    ReturnType<typeof makeOAuthTargetKernel>,
    "coordinateOAuthOwner" | "makeOAuthExecution"
  >,
) => {
  const { settle } = connectedSettlement;
  const { coordinateOAuthOwner, makeOAuthExecution } = target;

  const captured = <T extends STypes.Authority>(mapping: T): T => {
    const retained = captureOAuthMapping(mapping),
      codec = retained.subjectId;

    const subjectId = {
      ...codec,
      toNative: (subject: Parameters<typeof codec.toNative>[0]) =>
        Effect.map(codec.toNative(subject), S.nativeCopy),
      toSubject: (native: unknown) => codec.toSubject(S.nativeCopy(native)),
      equals: (a: unknown, b: unknown) => codec.equals(S.nativeCopy(a), S.nativeCopy(b)),
    };

    const ownership = retained.ownership;

    if (ownership.mode === "separate" && "encodeInsert" in ownership.external) {
      const encode = ownership.external.encodeInsert as (input: {
        readonly identity: typeof OAuthExternalIdentity.Type;
        readonly identityKey: string;
        readonly subjectId: unknown;
      }) => import("./owner").Row;

      return captureOAuthMapping({
        ...retained,
        subjectId,
        ownership: {
          ...ownership,
          external: {
            ...ownership.external,
            encodeInsert: (input: Parameters<typeof encode>[0]) =>
              encode({
                ...input,
                identity: snapshotOAuthSync(OAuthExternalIdentity, input.identity),
                subjectId: S.nativeCopy(input.subjectId),
              }),
          },
        },
      });
    }

    return captureOAuthMapping({ ...retained, subjectId });
  };

  const prepare = <Value, Encoded, A>(
    schema: Schema.Codec<Value, Encoded, never, never>,
    value: Value,
    callback: PrepareOAuthCommit<Value, A>,
  ) =>
    Effect.flatMap(CurrentOAuthTransaction, (owner) =>
      Effect.sync(() => {
        owner.guards.push(owner.journal.prepare(undefined));

        return callback(snapshotOAuthSync(schema, value), owner.journal);
      }),
    );

  const mutation =
    <Input, Value, Encoded>(
      mapping: STypes.Mapping,
      execute: OAuthExecution,
      body: (
        mapping: STypes.Mapping,
        input: Input,
      ) => Effect.Effect<
        Value,
        OAuthUnavailable | PersistenceMappingError | PlatformError.PlatformError,
        CurrentOAuthTransaction | Crypto.Crypto
      >,
      schema: Schema.Codec<Value, Encoded, never, never>,
    ) =>
    <A>(input: Input, callback: PrepareOAuthCommit<Value, A>) =>
      execute.run(
        Effect.flatMap(body(mapping, input), (value) => prepare(schema, value, callback)),
      );

  const read =
    <Input, Value>(
      mapping: STypes.Mapping,
      execute: OAuthExecution,
      body: (
        mapping: STypes.Mapping,
        input: Input,
      ) => Effect.Effect<
        Value,
        OAuthUnavailable | PersistenceMappingError | PlatformError.PlatformError,
        CurrentOAuthTransaction | Crypto.Crypto
      >,
    ) =>
    (input: Input) =>
      execute.run(body(mapping, input), false);

  const makeConnected = (
    mapping: STypes.Mapping,
    execute: OAuthExecution,
  ): OAuthConnectedPersistence["Service"] =>
    capturedOAuthService<OAuthConnectedPersistence["Service"]>(
      {
        claimSignIn: mutation(mapping, execute, SignIn.claimSignIn, M.OAuthSignInAccessClaim),
        inspectSignIn: read(mapping, execute, SignIn.inspectSignIn),
        settleSignIn: mutation(
          mapping,
          execute,
          SignIn.settleSignIn,
          M.OAuthConnectedSettlementDecision,
        ),
        capture: read(mapping, execute, F.capture),
        issue: mutation(mapping, execute, F.issue, M.OAuthConnectedIssueDecision),
        prepare: mutation(mapping, execute, F.prepare, M.OAuthConnectedIssueDecision),
        inspectPrepared: read(mapping, execute, F.inspectPrepared),
        preflight: read(mapping, execute, F.preflight),
        claim: mutation(mapping, execute, F.claim, M.OAuthConnectedClaimDecision),
        inspectGrant: read(mapping, execute, F.inspectGrant),
        settle: mutation(mapping, execute, settle, M.OAuthConnectedSettlementDecision),
        list: read(mapping, execute, Management.list),
        inspectDisconnect: read(mapping, execute, Management.inspectDisconnect),
        disconnect: mutation(
          mapping,
          execute,
          Management.disconnect,
          M.OAuthConnectedDisconnectDecision,
        ),
        inspectAccess: read(mapping, execute, A.inspectAccess),
        claimRefresh: mutation(mapping, execute, A.claimRefresh, M.OAuthConnectedRefreshDecision),
        settleRefresh: mutation(
          mapping,
          execute,
          A.settleRefresh,
          M.OAuthConnectedRefreshSettlement,
        ),
        admitUse: mutation(mapping, execute, A.admitUse, M.OAuthConnectedUseAdmission),
        cleanup: mutation(mapping, execute, Maintenance.cleanup, M.OAuthConnectedCleanupResult),
      },
      connectedInputs,
      execute.active,
      execute.poison,
    );

  const settled = Schema.Struct({ settled: Schema.Boolean });

  const makeRevocations = (
    mapping: STypes.Revocations,
    execute: OAuthExecution,
  ): OAuthConnectedRevocations["Service"] =>
    capturedOAuthService<OAuthConnectedRevocations["Service"]>(
      {
        claim: (input, callback) =>
          execute.run(
            Effect.flatMap(Maintenance.claimRevocation(mapping, input), (value) =>
              prepare(OAuthConnectedRevocationDecision, value, callback),
            ),
          ),
        settle: (input, callback) =>
          execute.run(
            Effect.flatMap(Maintenance.settleRevocation(mapping, input), (value) =>
              prepare(settled, value, callback),
            ),
          ),
      },
      connectedRevocationInputs,
      execute.active,
      execute.poison,
    );

  const makeTargetOAuthConnectedServices = (
    mapping: STypes.Mapping,
    configuration: OAuthTargetConfiguration,
  ) => {
    const retained = captured(mapping);

    return Effect.map(makeOAuthExecution(configuration, retained), (execution) => ({
      oauthConnectedPersistence: makeConnected(retained, execution),
    }));
  };

  const makeTargetOAuthConnectedRevocationServices = (
    mapping: STypes.Revocations,
    configuration: OAuthTargetConfiguration,
  ) => {
    const retained = captured(mapping);

    return Effect.map(makeOAuthExecution(configuration, retained), (execution) => ({
      oauthConnectedRevocations: makeRevocations(retained, execution),
    }));
  };

  const coordinateTargetOAuthConnected = <Transaction, A, E, R>(
    database: any,
    mapping: STypes.Mapping,
    configuration: OAuthTargetConfiguration,
    owner: (
      transaction: Transaction,
      services: { readonly oauthConnectedPersistence: OAuthConnectedPersistence["Service"] },
      append: (statement: Statement<any>) => void,
    ) => Effect.Effect<A, E, R>,
  ) =>
    coordinateOAuthOwner(
      database,
      captured(mapping),
      configuration,
      () => Effect.void,
      (value: STypes.Mapping, execution) => ({
        oauthConnectedPersistence: makeConnected(value, execution),
      }),
      owner,
    );

  const coordinateTargetOAuthConnectedRevocations = <Transaction, A, E, R>(
    database: any,
    mapping: STypes.Revocations,
    configuration: OAuthTargetConfiguration,
    owner: (
      transaction: Transaction,
      services: { readonly oauthConnectedRevocations: OAuthConnectedRevocations["Service"] },
      append: (statement: Statement<any>) => void,
    ) => Effect.Effect<A, E, R>,
  ) =>
    coordinateOAuthOwner(
      database,
      captured(mapping),
      configuration,
      () => Effect.void,
      (value: STypes.Revocations, execution) => ({
        oauthConnectedRevocations: makeRevocations(value, execution),
      }),
      owner,
    );

  const oauthConnectedPersistenceLayer = <E, R>(
    services: Effect.Effect<
      { readonly oauthConnectedPersistence: OAuthConnectedPersistence["Service"] },
      E,
      R
    >,
  ) =>
    Layer.effect(
      OAuthConnectedPersistence,
      Effect.map(services, (value) => value.oauthConnectedPersistence),
    );

  const oauthConnectedRevocationsLayer = <E, R>(
    services: Effect.Effect<
      { readonly oauthConnectedRevocations: OAuthConnectedRevocations["Service"] },
      E,
      R
    >,
  ) =>
    Layer.effect(
      OAuthConnectedRevocations,
      Effect.map(services, (value) => value.oauthConnectedRevocations),
    );

  return {
    makeConnected,
    makeRevocations,
    makeTargetOAuthConnectedServices,
    makeTargetOAuthConnectedRevocationServices,
    coordinateTargetOAuthConnected,
    coordinateTargetOAuthConnectedRevocations,
    oauthConnectedPersistenceLayer,
    oauthConnectedRevocationsLayer,
  };
};
