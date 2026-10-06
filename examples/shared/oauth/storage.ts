import { PersistenceMappingError } from "@yielded/auth-persistence";
import type { SubjectIdCodec } from "@yielded/auth-persistence/Adapter";
import * as Mapping from "@yielded/auth-persistence/OAuthPersistence";
import { eq, sql } from "@yielded/auth-persistence/OAuthPersistence";
import * as OAuth from "@yielded/auth/OAuth";
import { SubjectId } from "@yielded/auth/Schema";
import * as Sessions from "@yielded/auth/Sessions";
import { Context, DateTime, Effect, Layer, Schema } from "effect";
import { Base64Url } from "effect/encoding";
import { SqlClient } from "effect/sql";

export interface StorageOptions {
  readonly moduleId: string;
  readonly provider: string;
  readonly issuer: string;
  readonly externalSubject: string;
  readonly subjectId: string;
  /** Override only with a clock using the same integer-millisecond representation. */
  readonly clock?: Mapping.OAuthClock;
}

export const subjects = Mapping.table({
  name: "oauth_subject",
  columns: {
    id: { name: "id", type: "text" },
    status: { name: "status", type: "text" },
    securityRevision: { name: "securityRevision", type: "text" },
  },
  unique: [["id"]],
});

export const credentials = Mapping.table({
  name: "oauth_authority_credential",
  columns: {
    subjectId: { name: "subjectId", type: "text" },
    credentialId: { name: "credentialId", type: "text" },
    revision: { name: "revision", type: "text" },
    status: { name: "status", type: "text" },
  },
  unique: [["subjectId", "credentialId"]],
});

export const identities = Mapping.table({
  name: "oauth_identity",
  columns: {
    identityKey: { name: "identityKey", type: "text" },
    provider: { name: "provider", type: "text" },
    issuer: { name: "issuer", type: "text" },
    externalSubject: { name: "externalSubject", type: "text" },
    state: { name: "state", type: "text" },
    version: { name: "version", type: "text" },
    subjectId: { name: "subjectId", type: "text", nullable: true },
    reservation: { name: "reservation", type: "text", nullable: true },
  },
  unique: [["identityKey"]],
});

export const logins = Mapping.table({
  name: "oauth_login",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    credentialId: { name: "credentialId", type: "text" },
    subjectId: { name: "subjectId", type: "text" },
    identityKey: { name: "identityKey", type: "text" },
    credentialRevision: { name: "credentialRevision", type: "text" },
    status: { name: "status", type: "text" },
  },
  unique: [["credentialId"], ["identityKey"]],
});

export const signInFlows = Mapping.table({
  name: "oauth_sign_in_flow",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    flowId: { name: "flowId", type: "text" },
    commandId: { name: "commandId", type: "text", nullable: true },
    purpose: { name: "purpose", type: "text" },
    generation: { name: "generation", type: "integer", nullable: true },
    state: { name: "state", type: "text", nullable: true },
    version: { name: "version", type: "text", nullable: true },
    stateDigest: { name: "stateDigest", type: "text", nullable: true },
    binderVerifier: { name: "binderVerifier", type: "text", nullable: true },
    binderExpiresAt: { name: "binderExpiresAt", type: "integer", nullable: true },
    snapshot: { name: "snapshot", type: "text", nullable: true },
    issuedAt: { name: "issuedAt", type: "integer", nullable: true },
    expiresAt: { name: "expiresAt", type: "integer", nullable: true },
    claimId: { name: "claimId", type: "text", nullable: true },
    claimedAt: { name: "claimedAt", type: "integer", nullable: true },
    claimExpiresAt: { name: "claimExpiresAt", type: "integer", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
  },
  unique: [["moduleId", "flowId"], ["moduleId", "commandId"], ["stateDigest"]],
});

export const connectedFlows = Mapping.table({
  name: "oauth_connected_flow",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    flowId: { name: "flowId", type: "text" },
    commandId: { name: "commandId", type: "text", nullable: true },
    subjectId: { name: "subjectId", type: "text", nullable: true },
    clientKey: { name: "clientKey", type: "text", nullable: true },
    cohortKey: { name: "cohortKey", type: "text", nullable: true },
    state: { name: "state", type: "text", nullable: true },
    version: { name: "version", type: "text", nullable: true },
    stateDigest: { name: "stateDigest", type: "text", nullable: true },
    snapshot: { name: "snapshot", type: "text", nullable: true },
    claimId: { name: "claimId", type: "text", nullable: true },
    claimDigest: { name: "claimDigest", type: "text", nullable: true },
    claimOrder: { name: "claimOrder", type: "integer", nullable: true },
    claimedAt: { name: "claimedAt", type: "integer", nullable: true },
    claimExpiresAt: { name: "claimExpiresAt", type: "integer", nullable: true },
    expiresAt: { name: "expiresAt", type: "integer", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
    work: { name: "work", type: "text", nullable: true },
    custody: { name: "custody", type: "text", nullable: true },
  },
  unique: [["moduleId", "flowId"], ["moduleId", "commandId"], ["stateDigest"]],
});

export const grants = Mapping.table({
  name: "oauth_connected_grant",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    grantId: { name: "grantId", type: "text" },
    subjectId: { name: "subjectId", type: "text" },
    identityKey: { name: "identityKey", type: "text", nullable: true },
    activeIdentityKey: { name: "activeIdentityKey", type: "text", nullable: true },
    clientKey: { name: "clientKey", type: "text", nullable: true },
    cohortKey: { name: "cohortKey", type: "text", nullable: true },
    profileKey: { name: "profileKey", type: "text", nullable: true },
    grantVersion: { name: "grantVersion", type: "text", nullable: true },
    tokenVersion: { name: "tokenVersion", type: "text", nullable: true },
    cohortGeneration: { name: "cohortGeneration", type: "text", nullable: true },
    state: { name: "state", type: "text", nullable: true },
    version: { name: "version", type: "text", nullable: true },
    context: { name: "context", type: "text", nullable: true },
    sealed: { name: "sealed", type: "text", nullable: true },
    summary: { name: "summary", type: "text", nullable: true },
    revocationJobId: { name: "revocationJobId", type: "text", nullable: true },
    refreshWork: { name: "refreshWork", type: "text", nullable: true },
    refreshClaim: { name: "refreshClaim", type: "text", nullable: true },
    refreshClaimExpiresAt: { name: "refreshClaimExpiresAt", type: "integer", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
  },
  unique: [
    ["moduleId", "grantId"],
    ["moduleId", "subjectId", "profileKey", "activeIdentityKey"],
  ],
});

export const clients = Mapping.table({
  name: "oauth_connected_client",
  columns: {
    clientKey: { name: "clientKey", type: "text", nullable: true },
    provider: { name: "provider", type: "text" },
    issuer: { name: "issuer", type: "text" },
    clientRegistrationId: { name: "clientRegistrationId", type: "text" },
    counter: { name: "counter", type: "integer", nullable: true },
    version: { name: "version", type: "text", nullable: true },
  },
  unique: [["clientKey"]],
});

export const cohorts = Mapping.table({
  name: "oauth_connected_cohort",
  columns: {
    cohortKey: { name: "cohortKey", type: "text", nullable: true },
    clientKey: { name: "clientKey", type: "text" },
    identityKey: { name: "identityKey", type: "text" },
    generation: { name: "generation", type: "text", nullable: true },
    cutoff: { name: "cutoff", type: "integer", nullable: true },
    state: { name: "state", type: "text", nullable: true },
    version: { name: "version", type: "text", nullable: true },
  },
  unique: [["cohortKey"]],
});

export const admissions = Mapping.table({
  name: "oauth_connected_admission",
  columns: {
    admissionId: { name: "admissionId", type: "text" },
    moduleId: { name: "moduleId", type: "text" },
    grantId: { name: "grantId", type: "text" },
    subjectId: { name: "subjectId", type: "text" },
    identityKey: { name: "identityKey", type: "text", nullable: true },
    clientKey: { name: "clientKey", type: "text", nullable: true },
    cohortKey: { name: "cohortKey", type: "text", nullable: true },
    snapshot: { name: "snapshot", type: "text", nullable: true },
    admittedAt: { name: "admittedAt", type: "integer", nullable: true },
    expiresAt: { name: "expiresAt", type: "integer", nullable: true },
    version: { name: "version", type: "text", nullable: true },
  },
  unique: [["admissionId"]],
});

export const commands = Mapping.table({
  name: "oauth_connected_command",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    commandId: { name: "commandId", type: "text" },
    subjectId: { name: "subjectId", type: "text" },
    grantId: { name: "grantId", type: "text" },
    intent: { name: "intent", type: "text", nullable: true },
    decision: { name: "decision", type: "text", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
    version: { name: "version", type: "text", nullable: true },
  },
  unique: [["moduleId", "commandId"]],
});

export const revocations = Mapping.table({
  name: "oauth_connected_revocation",
  columns: {
    jobId: { name: "jobId", type: "text" },
    moduleId: { name: "moduleId", type: "text" },
    subjectId: { name: "subjectId", type: "text" },
    identityKey: { name: "identityKey", type: "text", nullable: true },
    clientKey: { name: "clientKey", type: "text", nullable: true },
    cohortKey: { name: "cohortKey", type: "text", nullable: true },
    grantId: { name: "grantId", type: "text" },
    snapshot: { name: "snapshot", type: "text", nullable: true },
    state: { name: "state", type: "text", nullable: true },
    claimId: { name: "claimId", type: "text", nullable: true },
    claimedAt: { name: "claimedAt", type: "integer", nullable: true },
    claimExpiresAt: { name: "claimExpiresAt", type: "integer", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
    version: { name: "version", type: "text", nullable: true },
  },
  unique: [["jobId"]],
});

export const requirement = Sessions.AuthenticationRequirement.make({
  maximumAgeMillis: 300_000,
  alternatives: [
    {
      factors: ["possession"],
      minimumCredentials: 1,
      userVerified: false,
      phishingResistant: false,
    },
  ],
});

const policyRevision = Sessions.SecurityRevision.make("owner-v1");

const order: Mapping.OAuthConnectedOrderCodec = {
  encode: (value) => value,
  decode: Schema.decodeUnknownSync(OAuth.OAuthInstant),
};

export const subjectId: SubjectIdCodec<string> = {
  toNative: (id) => Effect.succeed(id),
  toSubject: (id) =>
    Schema.decodeEffect(SubjectId)(id).pipe(
      Effect.mapError(() =>
        PersistenceMappingError.make({
          operation: "oauth-storage.subject",
          cause: undefined,
        }),
      ),
    ),
  equals: (left, right) => left === right,
};

export const subject = {
  table: subjects,
  id: "id",
  status: "status",
  securityRevision: "securityRevision",
  isActiveStatus: (value: unknown) => value === "active",
  activeCondition: eq(subjects.columns.status, "active"),
  decodeActionRequirement: () => requirement,
} satisfies Mapping.OAuthConnectedSubjectTable<typeof subjects>;

export const authority = {
  table: credentials,
  subjectId: "subjectId",
  credentialId: "credentialId",
  revision: "revision",
  status: "status",
  isActiveStatus: (value: unknown) => value === "active",
  activeCondition: eq(credentials.columns.status, "active"),
} satisfies Mapping.OAuthAuthorityReadTable<typeof credentials>;

export const credential = {
  table: logins,
  moduleId: "moduleId",
  credentialId: "credentialId",
  subjectId: "subjectId",
  identityKey: "identityKey",
  credentialRevision: "credentialRevision",
  status: "status",
  isActiveStatus: (value: unknown) => value === "active",
  activeCondition: eq(logins.columns.status, "active"),
} satisfies Mapping.OAuthCredentialReadTable<typeof logins>;

export const signInFlow = {
  table: signInFlows,
  moduleId: "moduleId",
  flowId: "flowId",
  commandId: "commandId",
  purpose: "purpose",
  generation: "generation",
  state: "state",
  version: "version",
  stateDigest: "stateDigest",
  binderVerifier: "binderVerifier",
  binderExpiresAt: "binderExpiresAt",
  snapshot: "snapshot",
  issuedAt: "issuedAt",
  expiresAt: "expiresAt",
  claimId: "claimId",
  claimedAt: "claimedAt",
  claimExpiresAt: "claimExpiresAt",
  retentionUntil: "retentionUntil",
  encodeInsert: (input) => input,
} satisfies Mapping.OAuthFlowTable<typeof signInFlows>;

export const ownership = {
  mode: "integrated",
  tuple: {
    table: identities,
    identityKey: "identityKey",
    provider: "provider",
    issuer: "issuer",
    externalSubject: "externalSubject",
    state: "state",
    version: "version",
    subjectId: "subjectId",
    reservation: "reservation",
    // Only startup provisioning may introduce an identity. A verified provider
    // response cannot expand the application's allowlist through connect.
    encodeInsert: () => {
      throw PersistenceMappingError.make({
        operation: "oauth-storage.unprovisioned-identity",
        cause: undefined,
      });
    },
  },
} satisfies Mapping.OAuthOwnershipMutation<typeof identities, typeof identities, string>;

const connectedFlow = {
  table: connectedFlows,
  moduleId: "moduleId",
  flowId: "flowId",
  commandId: "commandId",
  subjectId: "subjectId",
  clientKey: "clientKey",
  cohortKey: "cohortKey",
  state: "state",
  version: "version",
  stateDigest: "stateDigest",
  snapshot: "snapshot",
  claimId: "claimId",
  claimDigest: "claimDigest",
  claimOrder: "claimOrder",
  claimedAt: "claimedAt",
  claimExpiresAt: "claimExpiresAt",
  expiresAt: "expiresAt",
  retentionUntil: "retentionUntil",
  work: "work",
  custody: "custody",
  encodeInsert: ({ flow, subjectId }) => ({
    moduleId: flow.context.moduleId,
    flowId: flow.context.flowId,
    subjectId,
  }),
  encodeSignIn: ({ claim }) => ({
    moduleId: claim.flow.context.moduleId,
    flowId: claim.flow.context.flowId,
    subjectId: null,
  }),
} satisfies Mapping.OAuthConnectedFlowTable<typeof connectedFlows, string>;

const grant = {
  table: grants,
  moduleId: "moduleId",
  grantId: "grantId",
  subjectId: "subjectId",
  identityKey: "identityKey",
  activeIdentityKey: "activeIdentityKey",
  clientKey: "clientKey",
  cohortKey: "cohortKey",
  profileKey: "profileKey",
  grantVersion: "grantVersion",
  tokenVersion: "tokenVersion",
  cohortGeneration: "cohortGeneration",
  state: "state",
  version: "version",
  context: "context",
  sealed: "sealed",
  summary: "summary",
  revocationJobId: "revocationJobId",
  refreshWork: "refreshWork",
  refreshClaim: "refreshClaim",
  refreshClaimExpiresAt: "refreshClaimExpiresAt",
  retentionUntil: "retentionUntil",
  encodeInsert: ({ grant, subjectId }) => ({
    moduleId: grant.context.moduleId,
    grantId: grant.context.grantId,
    subjectId,
  }),
} satisfies Mapping.OAuthConnectedGrantTable<typeof grants, string>;

const client = {
  table: clients,
  clientKey: "clientKey",
  provider: "provider",
  issuer: "issuer",
  clientRegistrationId: "clientRegistrationId",
  counter: "counter",
  version: "version",
  encodeInsert: (configuration) => ({
    provider: configuration.provider,
    issuer: configuration.issuer,
    clientRegistrationId: configuration.profile.clientRegistrationId,
  }),
} satisfies Mapping.OAuthConnectedClientRegistrationTable<typeof clients>;

const cohort = {
  table: cohorts,
  cohortKey: "cohortKey",
  clientKey: "clientKey",
  identityKey: "identityKey",
  generation: "generation",
  cutoff: "cutoff",
  state: "state",
  version: "version",
  encodeInsert: (input) => input,
} satisfies Mapping.OAuthConnectedCohortTable<typeof cohorts>;

const admission = {
  table: admissions,
  admissionId: "admissionId",
  moduleId: "moduleId",
  grantId: "grantId",
  subjectId: "subjectId",
  identityKey: "identityKey",
  clientKey: "clientKey",
  cohortKey: "cohortKey",
  snapshot: "snapshot",
  admittedAt: "admittedAt",
  expiresAt: "expiresAt",
  version: "version",
  encodeInsert: ({ admissionId, grant, subjectId }) => ({
    admissionId,
    moduleId: grant.context.moduleId,
    grantId: grant.context.grantId,
    subjectId,
  }),
} satisfies Mapping.OAuthConnectedAdmissionTable<typeof admissions, string>;

const command = {
  table: commands,
  moduleId: "moduleId",
  commandId: "commandId",
  subjectId: "subjectId",
  grantId: "grantId",
  intent: "intent",
  decision: "decision",
  retentionUntil: "retentionUntil",
  version: "version",
  encodeInsert: ({ commandId, grant, subjectId }) => ({
    commandId,
    moduleId: grant.context.moduleId,
    grantId: grant.context.grantId,
    subjectId,
  }),
} satisfies Mapping.OAuthConnectedCommandTable<typeof commands, string>;

const job = {
  table: revocations,
  jobId: "jobId",
  moduleId: "moduleId",
  subjectId: "subjectId",
  identityKey: "identityKey",
  clientKey: "clientKey",
  cohortKey: "cohortKey",
  grantId: "grantId",
  snapshot: "snapshot",
  state: "state",
  claimId: "claimId",
  claimedAt: "claimedAt",
  claimExpiresAt: "claimExpiresAt",
  retentionUntil: "retentionUntil",
  version: "version",
  encodeInsert: ({ job, subjectId }) => ({
    jobId: job.context.jobId,
    moduleId: job.context.token.moduleId,
    grantId: job.context.token.grantId,
    subjectId,
  }),
} satisfies Mapping.OAuthConnectedRevocationJobTable<typeof revocations, string>;

// This example owns a fresh schema, not the removed OAuthApp schema. Applications
// should move these statements to their ordinary migration system.
const migrations = [
  `CREATE TABLE IF NOT EXISTS oauth_subject (
    "id" TEXT PRIMARY KEY NOT NULL, "status" TEXT NOT NULL, "securityRevision" TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS oauth_authority_credential (
    "subjectId" TEXT NOT NULL, "credentialId" TEXT NOT NULL, "revision" TEXT NOT NULL, "status" TEXT NOT NULL,
    UNIQUE("subjectId", "credentialId"))`,
  `CREATE TABLE IF NOT EXISTS oauth_identity (
    "identityKey" TEXT PRIMARY KEY NOT NULL, "provider" TEXT NOT NULL, "issuer" TEXT NOT NULL,
    "externalSubject" TEXT NOT NULL, "state" TEXT NOT NULL, "version" TEXT NOT NULL, "subjectId" TEXT, "reservation" TEXT)`,
  `CREATE TABLE IF NOT EXISTS oauth_login (
    "moduleId" TEXT NOT NULL, "credentialId" TEXT PRIMARY KEY NOT NULL, "subjectId" TEXT NOT NULL,
    "identityKey" TEXT NOT NULL UNIQUE, "credentialRevision" TEXT NOT NULL, "status" TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS oauth_login_owner ON oauth_login("identityKey", "subjectId")`,
  `CREATE TABLE IF NOT EXISTS oauth_sign_in_flow (
    "moduleId" TEXT NOT NULL, "flowId" TEXT NOT NULL, "commandId" TEXT, "purpose" TEXT NOT NULL,
    "generation" INTEGER, "state" TEXT, "version" TEXT, "stateDigest" TEXT, "binderVerifier" TEXT,
    "binderExpiresAt" INTEGER, "snapshot" TEXT, "issuedAt" INTEGER, "expiresAt" INTEGER,
    "claimId" TEXT, "claimedAt" INTEGER, "claimExpiresAt" INTEGER, "retentionUntil" INTEGER,
    UNIQUE("moduleId", "flowId"), UNIQUE("moduleId", "commandId"), UNIQUE("stateDigest"))`,
  `CREATE TABLE IF NOT EXISTS oauth_connected_flow (
    "moduleId" TEXT NOT NULL, "flowId" TEXT NOT NULL, "commandId" TEXT, "subjectId" TEXT, "clientKey" TEXT,
    "cohortKey" TEXT, "state" TEXT, "version" TEXT, "stateDigest" TEXT, "snapshot" TEXT, "claimId" TEXT,
    "claimDigest" TEXT, "claimOrder" INTEGER, "claimedAt" INTEGER, "claimExpiresAt" INTEGER,
    "expiresAt" INTEGER, "retentionUntil" INTEGER, "work" TEXT, "custody" TEXT,
    UNIQUE("moduleId", "flowId"), UNIQUE("moduleId", "commandId"), UNIQUE("stateDigest"))`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_flow_client ON oauth_connected_flow("clientKey")`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_flow_cohort ON oauth_connected_flow("cohortKey")`,
  `CREATE TABLE IF NOT EXISTS oauth_connected_grant (
    "moduleId" TEXT NOT NULL, "grantId" TEXT NOT NULL, "subjectId" TEXT NOT NULL, "identityKey" TEXT,
    "activeIdentityKey" TEXT, "clientKey" TEXT, "cohortKey" TEXT, "profileKey" TEXT, "grantVersion" TEXT,
    "tokenVersion" TEXT, "cohortGeneration" TEXT, "state" TEXT, "version" TEXT, "context" TEXT, "sealed" TEXT,
    "summary" TEXT, "revocationJobId" TEXT, "refreshWork" TEXT, "refreshClaim" TEXT,
    "refreshClaimExpiresAt" INTEGER, "retentionUntil" INTEGER, UNIQUE("moduleId", "grantId"),
    UNIQUE("moduleId", "subjectId", "profileKey", "activeIdentityKey"))`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_grant_identity ON oauth_connected_grant("identityKey")`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_grant_client ON oauth_connected_grant("clientKey")`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_grant_cohort ON oauth_connected_grant("cohortKey")`,
  `CREATE TABLE IF NOT EXISTS oauth_connected_client (
    "clientKey" TEXT UNIQUE, "provider" TEXT NOT NULL, "issuer" TEXT NOT NULL,
    "clientRegistrationId" TEXT NOT NULL, "counter" INTEGER, "version" TEXT)`,
  `CREATE TABLE IF NOT EXISTS oauth_connected_cohort (
    "cohortKey" TEXT UNIQUE, "clientKey" TEXT NOT NULL, "identityKey" TEXT NOT NULL,
    "generation" TEXT, "cutoff" INTEGER, "state" TEXT, "version" TEXT)`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_cohort_identity ON oauth_connected_cohort("identityKey")`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_cohort_client ON oauth_connected_cohort("clientKey")`,
  `CREATE TABLE IF NOT EXISTS oauth_connected_admission (
    "admissionId" TEXT PRIMARY KEY NOT NULL, "moduleId" TEXT NOT NULL, "grantId" TEXT NOT NULL,
    "subjectId" TEXT NOT NULL, "identityKey" TEXT, "clientKey" TEXT, "cohortKey" TEXT, "snapshot" TEXT,
    "admittedAt" INTEGER, "expiresAt" INTEGER, "version" TEXT)`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_admission_identity ON oauth_connected_admission("identityKey")`,
  `CREATE TABLE IF NOT EXISTS oauth_connected_command (
    "moduleId" TEXT NOT NULL, "commandId" TEXT NOT NULL, "subjectId" TEXT NOT NULL, "grantId" TEXT NOT NULL,
    "intent" TEXT, "decision" TEXT, "retentionUntil" INTEGER, "version" TEXT, UNIQUE("moduleId", "commandId"))`,
  `CREATE TABLE IF NOT EXISTS oauth_connected_revocation (
    "jobId" TEXT PRIMARY KEY NOT NULL, "moduleId" TEXT NOT NULL, "subjectId" TEXT NOT NULL,
    "identityKey" TEXT, "clientKey" TEXT, "cohortKey" TEXT, "grantId" TEXT NOT NULL, "snapshot" TEXT,
    "state" TEXT, "claimId" TEXT, "claimedAt" INTEGER, "claimExpiresAt" INTEGER, "retentionUntil" INTEGER, "version" TEXT)`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_revocation_identity ON oauth_connected_revocation("identityKey")`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_revocation_client ON oauth_connected_revocation("clientKey")`,
  `CREATE INDEX IF NOT EXISTS oauth_connected_revocation_cohort ON oauth_connected_revocation("cohortKey")`,
];

// Canonical adapter identity key: SHA-256 of versioned, length-prefixed UTF-8
// fields. Keep this at the app provisioning boundary until the adapter exports it.
export const identityKey = Effect.fn("OAuthStorage.identityKey")(function* (
  identity: typeof OAuth.OAuthExternalIdentity.Type,
) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });

  const fields = [
    "effect-auth/oauth-identity-key/v1",
    identity.provider,
    identity.issuer,
    identity.subject,
  ];

  const bytes = fields.map((value) => encoder.encode(value));

  if (bytes.some((value, i) => decoder.decode(value) !== fields[i])) {
    return yield* PersistenceMappingError.make({
      operation: "oauth-storage.identity",
      cause: undefined,
    });
  }
  const packed = new Uint8Array(bytes.reduce((size, value) => size + 4 + value.length, 0));
  const view = new DataView(packed.buffer);
  let offset = 0;

  for (const value of bytes) {
    view.setUint32(offset, value.length, false);
    packed.set(value, offset + 4);
    offset += 4 + value.length;
  }

  const digest = yield* Effect.tryPromise({
    try: () => globalThis.crypto.subtle.digest("SHA-256", packed),
    catch: () =>
      PersistenceMappingError.make({
        operation: "oauth-storage.identity",
        cause: undefined,
      }),
  });

  return "v1:" + Base64Url.encode(new Uint8Array(digest));
});

/** App-owned allowlist and explicit Effect SQL storage for OAuth sign-in and grants.
 * Sessions stay stateless. The single federated factor satisfies completion, so
 * pending authentication is not installed. Existing authority rows are never
 * reactivated or reassigned. Supply LifecycleHooks (empty is suitable here).
 */
export const makeMappings = (options: StorageOptions) =>
  Effect.gen(function* () {
    const moduleId = yield* Schema.decodeEffect(OAuth.OAuthModuleId)(options.moduleId);
    const localSubject = yield* Schema.decodeEffect(SubjectId)(options.subjectId);

    const identity = yield* Schema.decodeEffect(OAuth.OAuthExternalIdentity)({
      provider: options.provider,
      issuer: options.issuer,
      subject: options.externalSubject,
    });

    const key = yield* identityKey(identity);
    const credentialId = `oauth:${key}`;
    const sqlClient = yield* SqlClient.SqlClient;
    const postgres = sqlClient.onDialectOrElse({ pg: () => true, orElse: () => false });

    yield* sqlClient.withTransaction(
      Effect.gen(function* () {
        for (const statement of migrations)
          yield* sqlClient.unsafe(postgres ? statement.replaceAll("INTEGER", "BIGINT") : statement);
        yield* sqlClient`INSERT INTO oauth_subject (id, status, "securityRevision")
            VALUES (${localSubject}, 'active', 'initial') ON CONFLICT DO NOTHING`;
        yield* sqlClient`INSERT INTO oauth_identity
            ("identityKey", provider, issuer, "externalSubject", "subjectId", state, version, reservation)
            VALUES (${key}, ${identity.provider}, ${identity.issuer}, ${identity.subject},
              ${localSubject}, 'Owned', 'initial', NULL) ON CONFLICT DO NOTHING`;
        yield* sqlClient`INSERT INTO oauth_login
            ("moduleId", "credentialId", "subjectId", "identityKey", "credentialRevision", status)
            VALUES (${moduleId}, ${credentialId}, ${localSubject}, ${key}, 'initial', 'active')
            ON CONFLICT DO NOTHING`;
        yield* sqlClient`INSERT INTO oauth_authority_credential
            ("subjectId", "credentialId", revision, status)
            VALUES (${localSubject}, ${credentialId}, 'initial', 'active') ON CONFLICT DO NOTHING`;

        const [owner] = yield* sqlClient`SELECT * FROM oauth_identity WHERE "identityKey" = ${key}`;
        const [login] = yield* sqlClient`SELECT * FROM oauth_login WHERE "identityKey" = ${key}`;

        const [factor] = yield* sqlClient`SELECT * FROM oauth_authority_credential
            WHERE "subjectId" = ${localSubject} AND "credentialId" = ${credentialId}`;

        if (
          owner === undefined ||
          owner.state !== "Owned" ||
          owner.subjectId !== localSubject ||
          owner.provider !== identity.provider ||
          owner.issuer !== identity.issuer ||
          owner.externalSubject !== identity.subject ||
          login === undefined ||
          login.moduleId !== moduleId ||
          login.subjectId !== localSubject ||
          login.credentialId !== credentialId ||
          factor === undefined ||
          factor.revision !== login.credentialRevision
        ) {
          return yield* PersistenceMappingError.make({
            operation: "oauth-storage.provision-conflict",
            cause: undefined,
          });
        }
      }),
    );

    const common = { subject, authority, subjectId, clock: options.clock ?? Mapping.clock };

    const signIn = {
      ...common,
      ownership: {
        table: identities,
        identityKey: "identityKey",
        provider: "provider",
        issuer: "issuer",
        externalSubject: "externalSubject",
        subjectId: "subjectId",
        ownedCondition: sql`${eq(identities.columns.state, "Owned")}
          AND ${eq(identities.columns.identityKey, key)}
          AND ${eq(identities.columns.subjectId, localSubject)}`,
        decodeSubjectId: (row) => Schema.decodeUnknownSync(Schema.String)(row.subjectId),
      },
      credential,
      flow: signInFlow,
      constraints: Mapping.requiredOAuthSignInConstraints,
    } satisfies Mapping.OAuthSignInMapping<
      typeof subjects,
      typeof identities,
      typeof logins,
      typeof credentials,
      typeof signInFlows,
      string
    >;

    const connected = {
      ...common,
      ownership,
      flow: connectedFlow,
      grant,
      client,
      cohort,
      admission,
      command,
      signIn: { credential, flow: signInFlow },
      order,
      retentionMillis: 86_400_000,
      tupleConstraints: Mapping.requiredOAuthTupleConstraints,
      constraints: Mapping.requiredOAuthConnectedConstraints,
      revocation: {
        mode: "cohort",
        job,
        constraints: Mapping.requiredOAuthConnectedRevocationConstraints,
      },
      policy: {
        condition: (input) => {
          const configuration =
            input.kind === "action" || input.kind === "sign-in"
              ? input.configuration
              : input.grant?.configuration;

          const requestedModule =
            input.kind === "sign-in"
              ? input.credential.moduleId
              : input.kind === "action"
                ? input.authorization.challenge.moduleId
                : input.authorization.moduleId;

          if (
            input.subjectId !== localSubject ||
            requestedModule !== moduleId ||
            ((input.kind === "metadata" || input.kind === "use") &&
              input.authorization.policyRevision !== policyRevision) ||
            (configuration !== undefined &&
              (configuration.provider !== identity.provider ||
                configuration.issuer !== identity.issuer)) ||
            (input.grant !== undefined &&
              (input.grant.identity.provider !== identity.provider ||
                input.grant.identity.issuer !== identity.issuer ||
                input.grant.identity.subject !== identity.subject))
          )
            return sql`false`;

          return sql`exists(select 1 from ${identities} where ${identities.columns.identityKey} = ${key} and ${identities.columns.subjectId} = ${localSubject} and ${identities.columns.state} = 'Owned')`;
        },
      },
      externalReference: ({ identityKey, subjectId }) =>
        sql`exists(select 1 from ${logins} where ${eq(logins.columns.identityKey, identityKey)} and ${eq(logins.columns.subjectId, subjectId)})`,
    } satisfies Mapping.OAuthConnectedMapping<
      typeof subjects,
      typeof credentials,
      typeof identities,
      typeof identities,
      typeof connectedFlows,
      typeof grants,
      typeof clients,
      typeof cohorts,
      typeof admissions,
      typeof commands,
      string,
      typeof revocations
    >;

    return { signIn, connected, moduleId, localSubject, credentialId };
  });

export const makeServices = (mappings: Effect.Success<ReturnType<typeof makeMappings>>) =>
  Effect.gen(function* () {
    const { signIn, connected, moduleId, localSubject, credentialId } = mappings;
    const signInServices = yield* Mapping.makeOAuthSignInServices(signIn);
    const connectedServices = yield* Mapping.makeOAuthConnectedServices(connected);

    const revocationServices = yield* Mapping.makeOAuthConnectedRevocationServices({
      ...connected,
      job,
      constraints: Mapping.requiredOAuthConnectedRevocationConstraints,
    });

    const sessionServices = yield* Mapping.makeAuthenticationAuthorityServices({
      subjectId,
      subject: { ...subject, decodeRequirement: () => Effect.succeed(requirement) },
      credential: authority,
      isConstraintConflict: () => false,
    });

    const useAuthority = OAuth.OAuthConnectedUseAuthority.of({
      authorize: Effect.fn("OAuthStorage.authorizeUse")(function* (input) {
        if (
          input.invocation._tag !== "Authenticated" ||
          input.invocation.subjectId !== localSubject ||
          input.moduleId !== moduleId
        )
          return yield* OAuth.OAuthRejected.make({});

        const current = yield* connectedServices.oauthConnectedPersistence.capture({
          moduleId,
          subjectId: localSubject,
        });

        if (
          current === undefined ||
          !current.revision.credentials.some(
            (credential) => credential.credentialId === credentialId,
          )
        )
          return yield* OAuth.OAuthRejected.make({});
        const revision = current.revision;

        return {
          moduleId,
          revision,
          policyRevision,
          expiresAtMillis: DateTime.toEpochMillis(yield* DateTime.now) + 30_000,
          purpose: input.purpose,
          ...(input.grantId === undefined ? {} : { grantId: input.grantId }),
          ...(input.profileKey === undefined ? {} : { profileKey: input.profileKey }),
        };
      }),
    });

    return Context.make(OAuth.OAuthSignInPersistence, signInServices.oauthSignInPersistence).pipe(
      Context.add(OAuth.OAuthConnectedPersistence, connectedServices.oauthConnectedPersistence),
      Context.add(OAuth.OAuthConnectedRevocations, revocationServices.oauthConnectedRevocations),
      Context.add(Sessions.AuthenticationAuthority, sessionServices.authenticationAuthority),
      Context.add(OAuth.OAuthConnectedUseAuthority, useAuthority),
      // Connection management requires an application verifier for the exact
      // action challenge. Session assurance alone cannot authorize disconnect.
      Context.add(OAuth.OAuthConnectedActionEvidence, {
        verify: () => Effect.fail(OAuth.OAuthConnectedActionRequired.make({})),
      }),
    );
  });

export const makeStorage = (options: StorageOptions) =>
  Layer.effectContext(makeMappings(options).pipe(Effect.flatMap(makeServices)));
