import { OAuth, Sessions } from "@yielded/auth";
import { PersistenceMappingError } from "@yielded/auth-persistence";
import * as Mapping from "@yielded/auth-persistence/OAuthPersistence";
import { Context, Crypto, Effect, Layer, Schema } from "effect";
import { SqlClient } from "effect/sql";

import {
  authority,
  credential,
  identities,
  logins,
  makeMappings,
  makeServices,
  ownership,
  requirement,
  signInFlow,
  subject,
  subjectId,
} from "../../shared/oauth/storage";
import { AppAuth, moduleId, ownerId, profile, Registration } from "./oauth-lifecycle-model";

const { sql, eq } = Mapping;
const string = Schema.decodeUnknownSync(Schema.String);
const registrationJson = Schema.fromJsonString(Registration);

const intents = Mapping.table({
  name: "demo_oauth_registration",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    reference: { name: "reference", type: "text" },
    flowId: { name: "flowId", type: "text" },
    claimId: { name: "claimId", type: "text", nullable: true },
    identityKey: { name: "identityKey", type: "text", nullable: true },
    version: { name: "version", type: "text", nullable: true },
    state: { name: "state", type: "text", nullable: true },
    snapshot: { name: "snapshot", type: "text", nullable: true },
    commandId: { name: "commandId", type: "text", nullable: true },
    fingerprint: { name: "fingerprint", type: "text", nullable: true },
    pendingReference: { name: "pendingReference", type: "text", nullable: true },
    expiresAt: { name: "expiresAt", type: "integer", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
  },
  unique: [
    ["moduleId", "reference"],
    ["moduleId", "flowId"],
  ],
});

const registrationCommands = Mapping.table({
  name: "demo_oauth_registration_command",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    commandId: { name: "commandId", type: "text" },
    reference: { name: "reference", type: "text", nullable: true },
    identityKey: { name: "identityKey", type: "text", nullable: true },
    fingerprint: { name: "fingerprint", type: "text", nullable: true },
    intentSnapshot: { name: "intentSnapshot", type: "text", nullable: true },
    applicationSnapshot: { name: "applicationSnapshot", type: "text", nullable: true },
    provisioningIdentity: { name: "provisioningIdentity", type: "text", nullable: true },
    decision: { name: "decision", type: "text", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
  },
  unique: [["moduleId", "commandId"]],
});

const unlinkCommands = Mapping.table({
  name: "demo_oauth_unlink_command",
  columns: {
    moduleId: { name: "moduleId", type: "text" },
    commandId: { name: "commandId", type: "text" },
    subjectId: { name: "subjectId", type: "text" },
    credentialId: { name: "credentialId", type: "text" },
    intentSnapshot: { name: "intentSnapshot", type: "text", nullable: true },
    decision: { name: "decision", type: "text", nullable: true },
    retentionUntil: { name: "retentionUntil", type: "integer", nullable: true },
  },
  unique: [["moduleId", "commandId"]],
});

const intent = {
  table: intents,
  moduleId: "moduleId",
  reference: "reference",
  flowId: "flowId",
  claimId: "claimId",
  identityKey: "identityKey",
  version: "version",
  state: "state",
  snapshot: "snapshot",
  commandId: "commandId",
  fingerprint: "fingerprint",
  pendingReference: "pendingReference",
  expiresAt: "expiresAt",
  retentionUntil: "retentionUntil",
  encodeInsert: (value) => ({
    moduleId: value.context.moduleId,
    reference: value.reference,
    flowId: value.context.flowId,
  }),
} satisfies Mapping.OAuthRegistrationIntentTable<typeof intents>;

const mutableOwnership = {
  ...ownership,
  tuple: {
    ...ownership.tuple,
    encodeInsert: ({ identityKey, identity }) => ({
      identityKey,
      provider: identity.provider,
      issuer: identity.issuer,
      externalSubject: identity.subject,
    }),
  },
} satisfies Mapping.OAuthOwnershipMutation<typeof identities, typeof identities, string>;

const mutableCredential = {
  ...credential,
  removal: "delete",
  encodeInsert: (value) => ({ ...value, status: "active" }),
} satisfies Mapping.OAuthCredentialTable<typeof logins, string>;

const mutableAuthority = {
  ...authority,
  encodeInsert: (value) => ({ ...value, status: "active" }),
} satisfies Mapping.OAuthAuthorityTable<typeof authority.table, string>;

/** App-owned migration and policy for this disposable CLI consumer only. */
export const makeLifecycleStorage = Effect.gen(function* () {
  const client = yield* SqlClient.SqlClient;
  const crypto = yield* Crypto.Crypto;

  const uuid = crypto.randomUUIDv4.pipe(
    Effect.mapError((cause) => PersistenceMappingError.make({ operation: "demo.allocate", cause })),
  );

  const dialect = client.onDialectOrElse({
    pg: () => "pg" as const,
    orElse: () => "sqlite" as const,
  });

  const base = yield* makeMappings({
    moduleId,
    subjectId: ownerId,
    provider: profile.provider,
    issuer: "https://www.strava.com",
    externalSubject: "123",
  });

  const integer = dialect === "pg" ? "BIGINT" : "INTEGER";

  yield* client.withTransaction(
    Effect.gen(function* () {
      yield* client.unsafe(`CREATE TABLE IF NOT EXISTS demo_oauth_registration (
      "moduleId" TEXT NOT NULL, reference TEXT NOT NULL, "flowId" TEXT NOT NULL,
      "claimId" TEXT, "identityKey" TEXT, version TEXT, state TEXT, snapshot TEXT,
      "commandId" TEXT, fingerprint TEXT, "pendingReference" TEXT, "expiresAt" ${integer},
      "retentionUntil" ${integer}, UNIQUE("moduleId", reference), UNIQUE("moduleId", "flowId"))`);
      yield* client.unsafe(`CREATE TABLE IF NOT EXISTS demo_oauth_registration_command (
      "moduleId" TEXT NOT NULL, "commandId" TEXT NOT NULL, reference TEXT, "identityKey" TEXT,
      fingerprint TEXT, "intentSnapshot" TEXT, "applicationSnapshot" TEXT, "provisioningIdentity" TEXT,
      decision TEXT, "retentionUntil" ${integer}, UNIQUE("moduleId", "commandId"))`);
      yield* client.unsafe(`CREATE TABLE IF NOT EXISTS demo_oauth_unlink_command (
      "moduleId" TEXT NOT NULL, "commandId" TEXT NOT NULL, "subjectId" TEXT NOT NULL,
      "credentialId" TEXT NOT NULL, "intentSnapshot" TEXT, decision TEXT, "retentionUntil" ${integer},
      UNIQUE("moduleId", "commandId"))`);
    }),
  );

  const signIn = {
    ...base.signIn,
    ownership: { ...base.signIn.ownership, ownedCondition: eq(identities.columns.state, "Owned") },
  };

  const registration = {
    mode: "atomic",
    ownership: mutableOwnership,
    intent,
    command: {
      table: registrationCommands,
      moduleId: "moduleId",
      commandId: "commandId",
      reference: "reference",
      identityKey: "identityKey",
      fingerprint: "fingerprint",
      intentSnapshot: "intentSnapshot",
      applicationSnapshot: "applicationSnapshot",
      provisioningIdentity: "provisioningIdentity",
      decision: "decision",
      retentionUntil: "retentionUntil",
      encodeInsert: ({ intent, commandId }) => ({ moduleId: intent.context.moduleId, commandId }),
    },
    clock: Mapping.clock,
    tupleConstraints: Mapping.requiredOAuthTupleConstraints,
    constraints: Mapping.requiredOAuthRegistrationConstraints,
    inspect: ({ registration }) =>
      Effect.succeed({
        fingerprint: `demo-v1:${Schema.encodeSync(registrationJson)(registration)}`,
        eligible: true,
      }),
    snapshot: (registration) =>
      Schema.decodeEffect(Registration)(registration).pipe(
        Effect.mapError((cause) =>
          PersistenceMappingError.make({ operation: "demo.registration", cause }),
        ),
      ),
    application: {
      encode: Schema.encodeSync(registrationJson),
      decode: Schema.decodeSync(registrationJson),
    },
    eligibility: { admission: () => sql`true`, postcondition: () => sql`true` },
    allocateProvisioningIdentity: uuid,
    retentionMillis: 86_400_000,
    subjectId,
    subject,
    credential: mutableCredential,
    authority: mutableAuthority,
    allocateSubjectId: uuid,
    allocateCredentialId: uuid,
    allocateRevision: Effect.succeed(Sessions.SecurityRevision.make("0")),
    encodeSubjectInsert: (_input, ids) => ({
      id: ids.subjectId,
      status: "active",
      securityRevision: ids.securityRevision,
    }),
  } satisfies Mapping.OAuthRegistrationMapping<
    typeof Registration.Type,
    typeof subject.table,
    typeof identities,
    typeof logins,
    typeof authority.table,
    typeof identities,
    typeof intents,
    typeof registrationCommands,
    string
  >;

  const accounts = {
    subject: {
      ...subject,
      decodeAuthenticationRequirement: () => requirement,
      nextSecurityRevision: (current) =>
        Sessions.SecurityRevision.make(current === "initial" ? "1" : String(BigInt(current) + 1n)),
    },
    ownership: mutableOwnership,
    credential: mutableCredential,
    authority: mutableAuthority,
    flow: signInFlow,
    command: {
      table: unlinkCommands,
      moduleId: "moduleId",
      commandId: "commandId",
      subjectId: "subjectId",
      credentialId: "credentialId",
      intentSnapshot: "intentSnapshot",
      decision: "decision",
      retentionUntil: "retentionUntil",
      encodeInsert: ({ moduleId, commandId, credential }) => ({
        moduleId,
        commandId,
        subjectId: credential.revision.subjectId,
        credentialId: credential.credentialId,
      }),
    },
    subjectId,
    clock: Mapping.clock,
    constraints: {
      ...Mapping.requiredOAuthSignInConstraints,
      ...Mapping.requiredOAuthAccountsConstraints,
    },
    tupleConstraints: Mapping.requiredOAuthTupleConstraints,
    eligibility: [
      Mapping.oauthEligibilityTable<typeof logins, string>({
        table: logins,
        subjectId: "subjectId",
        credentialId: "credentialId",
        revision: "credentialRevision",
        scope: "demo-oauth-logins",
        condition: () => eq(logins.columns.status, "active"),
        decode: (row) => ({
          credentialId: string(row.credentialId),
          revision: Schema.decodeUnknownSync(Sessions.SecurityRevision)(row.credentialRevision),
          usablePrimary: row.status === "active",
          factors: ["possession"],
          userVerified: false,
          phishingResistant: false,
        }),
      }),
    ],
    cleanup: [],
    metadata: { condition: () => sql`true` },
    sessionInvalidation: "original-absolute-expiry",
    ...Mapping.oauthConnectedOwnershipReferences(base.connected, dialect),
    allocateCredentialId: uuid,
    allocateRevision: uuid.pipe(Effect.map((value) => Sessions.SecurityRevision.make(value))),
  } satisfies Mapping.OAuthAccountsMapping<
    typeof subject.table,
    typeof identities,
    typeof logins,
    typeof authority.table,
    typeof signInFlow.table,
    typeof identities,
    typeof unlinkCommands,
    string
  >;

  const registrationIntents = yield* Mapping.makeOAuthRegistrationIntentServices({
    signIn,
    ownership: mutableOwnership,
    intent,
    tupleConstraints: Mapping.requiredOAuthTupleConstraints,
    registrationConstraints: {
      intentReference: Mapping.requiredOAuthRegistrationConstraints.intentReference,
      intentFlow: Mapping.requiredOAuthRegistrationConstraints.intentFlow,
    },
    eligibility: { condition: () => sql`true` },
  });

  const registrationServices = yield* Mapping.makeOAuthRegistrationServices(registration);
  const accountServices = yield* Mapping.makeOAuthAccountsServices(accounts);
  const services = yield* makeServices({ ...base, signIn });

  return services.pipe(
    Context.add(OAuth.OAuthRegistrationIntents, registrationIntents.oauthRegistrationIntents),
    Context.add(OAuth.OAuthAccountsPersistence, accountServices.oauthAccountsPersistence),
    Context.add(
      AppAuth.strategies.registration.registration.RegistrationAuthority,
      registrationServices.registrationAuthority,
    ),
  );
});

export const LifecycleStorageLive = Layer.effectContext(makeLifecycleStorage);
