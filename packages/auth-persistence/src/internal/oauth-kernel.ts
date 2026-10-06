import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";

import { OAuthAccounts } from "./oauth/accounts";
import { OAuthConnectedAccess } from "./oauth/connected-access";
import { OAuthConnectedCollection } from "./oauth/connected-collection";
import { OAuthConnectedCustody } from "./oauth/connected-custody";
import { OAuthConnectedFlow } from "./oauth/connected-flow";
import { OAuthConnectedMaintenance } from "./oauth/connected-maintenance";
import { OAuthConnectedManagement } from "./oauth/connected-management";
import { makeOAuthConnectedReferenceKernel } from "./oauth/connected-reference";
import { OAuthConnectedSettlement } from "./oauth/connected-settlement";
import { OAuthConnectedSignIn } from "./oauth/connected-sign-in";
import { OAuthConnectedState } from "./oauth/connected-state";
import {
  OAuthConnectedTarget,
  oauthConnectedPersistenceLayer,
  oauthConnectedRevocationsLayer,
} from "./oauth/connected-target";
import { OAuthFlow } from "./oauth/flow";
import { OAuthTransactionExecution } from "./oauth/owner";
import { OAuthQueryCompiler } from "./oauth/query-compiler";
import { OAuthRegistration } from "./oauth/registration";
import { captureOAuthMapping, unavailable } from "./oauth/state";
import {
  OAuthTarget,
  oauthAccountsPersistenceLayer,
  oauthSignInPersistenceLayer,
  oauthRegistrationIntentsLayer,
  oauthRegistrationAuthorityLayer,
} from "./oauth/target";
import type { QueryOperations } from "./query-operations";
import { requireStandalone } from "./standalone";
import { makeTransactionExecutionKernel } from "./transaction-execution-kernel";
import { makeTransactionKernel } from "./transaction-kernel";

export type OAuthKernel = ReturnType<typeof makeOAuthKernel>;

/** Adapter composition root. Shared operation Layers acquire their dependencies;
 * database and transaction services are still resolved by each operation. */
export const makeOAuthKernel = (
  operations: QueryOperations,
  dialect: (table: object) => "pg" | "sqlite" | "mysql",
) => {
  const transactions = makeTransactionKernel(operations);
  const connectedReference = makeOAuthConnectedReferenceKernel(operations, dialect);

  const compilerLive = Layer.succeed(OAuthQueryCompiler, {
    ...operations,
    ...transactions.makeTransactionRows(unavailable),
    both: transactions.both,
    connectedReferenceCondition: connectedReference.connectedReferenceCondition,
  });

  const executionLive = Layer.succeed(
    OAuthTransactionExecution,
    makeTransactionExecutionKernel(transactions),
  );

  const flowLive = OAuthFlow.layer.pipe(Layer.provide([compilerLive]));
  const registrationLive = OAuthRegistration.layer.pipe(Layer.provide([compilerLive, flowLive]));

  const accountsLive = OAuthAccounts.layer.pipe(
    Layer.provide([compilerLive, flowLive, registrationLive]),
  );

  const targetLive = OAuthTarget.layer.pipe(
    Layer.provide([compilerLive, accountsLive, flowLive, registrationLive, executionLive]),
  );

  const connectedStateLive = OAuthConnectedState.layer.pipe(
    Layer.provide([compilerLive, flowLive]),
  );

  const connectedFlowLive = OAuthConnectedFlow.layer.pipe(
    Layer.provide([compilerLive, connectedStateLive, registrationLive]),
  );

  const connectedCustodyLive = OAuthConnectedCustody.layer.pipe(
    Layer.provide([compilerLive, connectedStateLive]),
  );

  const connectedCollectionLive = OAuthConnectedCollection.layer.pipe(
    Layer.provide([compilerLive, connectedCustodyLive, connectedFlowLive, connectedStateLive]),
  );

  const connectedSettlementLive = OAuthConnectedSettlement.layer.pipe(
    Layer.provide([compilerLive, connectedCustodyLive, connectedFlowLive, connectedStateLive]),
  );

  const connectedAccessLive = OAuthConnectedAccess.layer.pipe(
    Layer.provide([
      compilerLive,
      connectedCustodyLive,
      connectedFlowLive,
      connectedSettlementLive,
      connectedStateLive,
    ]),
  );

  const connectedManagementLive = OAuthConnectedManagement.layer.pipe(
    Layer.provide([
      compilerLive,
      connectedAccessLive,
      connectedCustodyLive,
      connectedFlowLive,
      connectedStateLive,
    ]),
  );

  const connectedMaintenanceLive = OAuthConnectedMaintenance.layer.pipe(
    Layer.provide([
      compilerLive,
      connectedCollectionLive,
      connectedCustodyLive,
      connectedFlowLive,
      connectedStateLive,
    ]),
  );

  const connectedSignInLive = OAuthConnectedSignIn.layer.pipe(
    Layer.provide([
      compilerLive,
      connectedCustodyLive,
      connectedFlowLive,
      connectedSettlementLive,
      connectedStateLive,
      flowLive,
    ]),
  );

  const connectedTargetLive = OAuthConnectedTarget.layer.pipe(
    Layer.provide([
      connectedAccessLive,
      connectedFlowLive,
      connectedMaintenanceLive,
      connectedManagementLive,
      connectedSettlementLive,
      connectedSignInLive,
      connectedStateLive,
      targetLive,
    ]),
  );

  // Preserve constructor-time snapshots before deferred Layer acquisition.
  const makeTargetOAuthSignInServices: OAuthTarget["Service"]["makeTargetOAuthSignInServices"] = (
    mapping,
    configuration,
  ) => {
    const captured = captureOAuthMapping(mapping);

    return Effect.flatMap(OAuthTarget, (service) =>
      service.makeTargetOAuthSignInServices(captured, configuration),
    ).pipe(Effect.provide(targetLive));
  };

  const makeTargetOAuthRegistrationIntentServices: OAuthTarget["Service"]["makeTargetOAuthRegistrationIntentServices"] =
    (mapping, configuration) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthTarget, (service) =>
        service.makeTargetOAuthRegistrationIntentServices(captured, configuration),
      ).pipe(Effect.provide(targetLive));
    };

  const makeTargetOAuthRegistrationServices: OAuthTarget["Service"]["makeTargetOAuthRegistrationServices"] =
    (mapping, configuration) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthTarget, (service) =>
        service.makeTargetOAuthRegistrationServices(captured, configuration),
      ).pipe(Effect.provide(targetLive));
    };

  const makeTargetOAuthAccountsServices: OAuthTarget["Service"]["makeTargetOAuthAccountsServices"] =
    (mapping, configuration) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthTarget, (service) =>
        service.makeTargetOAuthAccountsServices(captured, configuration),
      ).pipe(Effect.provide(targetLive));
    };

  const coordinateTargetOAuthRegistration: OAuthTarget["Service"]["coordinateTargetOAuthRegistration"] =
    (database, mapping, configuration, owner) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthTarget, (service) =>
        service.coordinateTargetOAuthRegistration(database, captured, configuration, owner),
      ).pipe(Effect.provide(targetLive));
    };

  const coordinateTargetOAuthSignIn: OAuthTarget["Service"]["coordinateTargetOAuthSignIn"] = (
    database,
    mapping,
    configuration,
    owner,
  ) => {
    const captured = captureOAuthMapping(mapping);

    return Effect.flatMap(OAuthTarget, (service) =>
      service.coordinateTargetOAuthSignIn(database, captured, configuration, owner),
    ).pipe(Effect.provide(targetLive));
  };

  const coordinateTargetOAuthRegistrationIntents: OAuthTarget["Service"]["coordinateTargetOAuthRegistrationIntents"] =
    (database, mapping, configuration, owner) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthTarget, (service) =>
        service.coordinateTargetOAuthRegistrationIntents(database, captured, configuration, owner),
      ).pipe(Effect.provide(targetLive));
    };

  const coordinateTargetOAuthAccounts: OAuthTarget["Service"]["coordinateTargetOAuthAccounts"] = (
    database,
    mapping,
    configuration,
    owner,
  ) => {
    const captured = captureOAuthMapping(mapping);

    return Effect.flatMap(OAuthTarget, (service) =>
      service.coordinateTargetOAuthAccounts(database, captured, configuration, owner),
    ).pipe(Effect.provide(targetLive));
  };

  const makeTargetOAuthConnectedServices: OAuthConnectedTarget["Service"]["makeTargetOAuthConnectedServices"] =
    (mapping, configuration) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthConnectedTarget, (service) =>
        service.makeTargetOAuthConnectedServices(captured, configuration),
      ).pipe(Effect.provide(connectedTargetLive));
    };

  const makeTargetOAuthConnectedRevocationServices: OAuthConnectedTarget["Service"]["makeTargetOAuthConnectedRevocationServices"] =
    (mapping, configuration) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthConnectedTarget, (service) =>
        service.makeTargetOAuthConnectedRevocationServices(captured, configuration),
      ).pipe(Effect.provide(connectedTargetLive));
    };

  const coordinateTargetOAuthConnected: OAuthConnectedTarget["Service"]["coordinateTargetOAuthConnected"] =
    (database, mapping, configuration, owner) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthConnectedTarget, (service) =>
        service.coordinateTargetOAuthConnected(database, captured, configuration, owner),
      ).pipe(Effect.provide(connectedTargetLive));
    };

  const coordinateTargetOAuthConnectedRevocations: OAuthConnectedTarget["Service"]["coordinateTargetOAuthConnectedRevocations"] =
    (database, mapping, configuration, owner) => {
      const captured = captureOAuthMapping(mapping);

      return Effect.flatMap(OAuthConnectedTarget, (service) =>
        service.coordinateTargetOAuthConnectedRevocations(database, captured, configuration, owner),
      ).pipe(Effect.provide(connectedTargetLive));
    };

  const sqlClientOAuthStandaloneGuard = (service: SqlClient["transactionService"] | undefined) =>
    requireStandalone(unavailable, service);

  return {
    target: {
      makeTargetOAuthSignInServices,
      makeTargetOAuthRegistrationIntentServices,
      makeTargetOAuthRegistrationServices,
      makeTargetOAuthAccountsServices,
      coordinateTargetOAuthRegistration,
      coordinateTargetOAuthSignIn,
      coordinateTargetOAuthRegistrationIntents,
      coordinateTargetOAuthAccounts,
      sqlClientOAuthStandaloneGuard,
      oauthAccountsPersistenceLayer,
      oauthSignInPersistenceLayer,
      oauthRegistrationIntentsLayer,
      oauthRegistrationAuthorityLayer,
    },
    connectedTarget: {
      makeTargetOAuthConnectedServices,
      makeTargetOAuthConnectedRevocationServices,
      coordinateTargetOAuthConnected,
      coordinateTargetOAuthConnectedRevocations,
      oauthConnectedPersistenceLayer,
      oauthConnectedRevocationsLayer,
    },
    connectedReference,
  };
};
