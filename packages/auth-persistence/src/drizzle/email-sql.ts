import { makeEmailKernel } from "../internal/email-kernel";
import { completeProofPlanIn } from "./proof-sql";
import { drizzleQueryOperations } from "./query-operations";

export { CurrentEmailSql } from "../internal/email-kernel";

export type {
  EmailSqlQuery,
  EmailSqlDatabase,
  EmailSqlConfiguration,
  CurrentAddress,
} from "../internal/email-kernel";

export const {
  validEmailSignInConstraints,
  emailLookupQuery,
  decodeEmailSnapshot,
  makeSqlEmailSignInTargets,
  currentAddress,
  sameEmailRevision,
  snapshotEmailMutation,
  validateEmailAuthority,
  makeSqlEmailAddressPersistence,
} = makeEmailKernel(drizzleQueryOperations, { completeProofPlanIn });
