/** Primitives for application-owned persistence implementations and transaction adapters. */
export { CurrentCommitJournal } from "./hooks/commit";
export { AuthStoreDecisions, type ChallengeConsumeDecision } from "./internal/AuthStoreDecisions";
export { reportAuthFailure, reportPersistenceFailure } from "./internal/diagnostics";
export { cryptoLayer, hooksLayer } from "./auth/defaults";
export { digest, randomId } from "./totp/crypto";
