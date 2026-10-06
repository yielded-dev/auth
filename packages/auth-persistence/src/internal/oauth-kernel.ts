import { makeOAuthAccountsKernel } from "./oauth/accounts";
import { makeOAuthConnectedAccessKernel } from "./oauth/connected-access";
import { makeOAuthConnectedCollectionKernel } from "./oauth/connected-collection";
import { makeOAuthConnectedCustodyKernel } from "./oauth/connected-custody";
import { makeOAuthConnectedFlowKernel } from "./oauth/connected-flow";
import { makeOAuthConnectedMaintenanceKernel } from "./oauth/connected-maintenance";
import { makeOAuthConnectedManagementKernel } from "./oauth/connected-management";
import { makeOAuthConnectedReferenceKernel } from "./oauth/connected-reference";
import { makeOAuthConnectedSettlementKernel } from "./oauth/connected-settlement";
import { makeOAuthConnectedSignInKernel } from "./oauth/connected-sign-in";
import { makeOAuthConnectedStateKernel } from "./oauth/connected-state";
import { makeOAuthConnectedTargetKernel } from "./oauth/connected-target";
import { makeOAuthFlowKernel } from "./oauth/flow";
import { makeOAuthOwnerKernel } from "./oauth/owner";
import { makeOAuthRegistrationKernel } from "./oauth/registration";
import { makeOAuthTargetKernel } from "./oauth/target";
import type { QueryOperations } from "./query-operations";
import { makeTransactionExecutionKernel } from "./transaction-execution-kernel";
import { makeTransactionKernel } from "./transaction-kernel";
export type OAuthKernel = ReturnType<typeof makeOAuthKernel>;

/** Shared OAuth transitions; adapters supply only query compilation and transaction semantics. */
export const makeOAuthKernel = (
  operations: QueryOperations,
  dialect: (table: object) => "pg" | "sqlite" | "mysql",
) => {
  const transactions = makeTransactionKernel(operations);
  const execution = makeTransactionExecutionKernel(transactions);
  const owner = makeOAuthOwnerKernel(transactions);
  const flow = makeOAuthFlowKernel(operations, owner);
  const registration = makeOAuthRegistrationKernel(operations, flow, owner);
  const accounts = makeOAuthAccountsKernel(operations, flow, owner, registration);
  const target = makeOAuthTargetKernel(operations, accounts, flow, owner, registration, execution);
  const connectedState = makeOAuthConnectedStateKernel(operations, flow, owner);

  const connectedReference = makeOAuthConnectedReferenceKernel(
    operations,
    connectedState,
    owner,
    dialect,
  );

  const connectedFlow = makeOAuthConnectedFlowKernel(
    operations,
    connectedState,
    owner,
    registration,
  );

  const connectedCustody = makeOAuthConnectedCustodyKernel(operations, connectedState, owner);

  const connectedCollection = makeOAuthConnectedCollectionKernel(
    operations,
    connectedCustody,
    connectedFlow,
    connectedReference,
    connectedState,
    owner,
  );

  const connectedSettlement = makeOAuthConnectedSettlementKernel(
    operations,
    connectedCustody,
    connectedFlow,
    connectedState,
    owner,
  );

  const connectedAccess = makeOAuthConnectedAccessKernel(
    operations,
    connectedCustody,
    connectedFlow,
    connectedSettlement,
    connectedState,
    owner,
  );

  const connectedManagement = makeOAuthConnectedManagementKernel(
    operations,
    connectedAccess,
    connectedCustody,
    connectedFlow,
    connectedState,
    owner,
  );

  const connectedMaintenance = makeOAuthConnectedMaintenanceKernel(
    operations,
    connectedCollection,
    connectedCustody,
    connectedFlow,
    connectedState,
    owner,
  );

  const connectedSignIn = makeOAuthConnectedSignInKernel(
    operations,
    connectedCustody,
    connectedFlow,
    connectedSettlement,
    connectedState,
    flow,
    owner,
  );

  const connectedTarget = makeOAuthConnectedTargetKernel(
    connectedAccess,
    connectedFlow,
    connectedMaintenance,
    connectedManagement,
    connectedSettlement,
    connectedSignIn,
    connectedState,
    target,
  );

  return {
    owner,
    flow,
    registration,
    accounts,
    target,
    connectedState,
    connectedReference,
    connectedFlow,
    connectedCustody,
    connectedCollection,
    connectedSettlement,
    connectedAccess,
    connectedManagement,
    connectedMaintenance,
    connectedSignIn,
    connectedTarget,
  };
};
