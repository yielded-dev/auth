export {
  ActionContext,
  Functions,
  type FunctionReferences,
  OAuthServerPersistence,
} from "./internal/persistence";

export {
  DocumentFunctions,
  DocumentStore,
  Transaction,
  PersistenceUnavailable,
  TransactionConflict,
} from "./internal/documents";

export {
  Subject,
  Identifier,
  AuthorityCredential,
  identityPartitions,
  identifierKey,
  bindIdentifier,
  invalidateSubject,
} from "./internal/identity";

export { PasswordPersistence, makePasswordRegistration } from "./internal/passwords";
export { makeSessions } from "./internal/sessions";
export { ProofPersistence } from "./internal/proofs";
export { managed, type ManagedOptions } from "./internal/managed";
