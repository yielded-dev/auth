import * as M from "@yielded/auth/Passkey";
import { Context, Effect, Schema } from "effect";
import { SqlClient } from "effect/sql";
import type { Fragment } from "effect/sql/Statement";

import {
  PersistenceConfigurationError,
  type MappingInput,
  type PasskeyFeature,
} from "./configuration";
import { PersistenceMappingError } from "./mapping-error";
import {
  requiredPasskeyCredentialConstraints,
  requiredPasskeyPersistenceConstraints,
} from "./models/passkey-model";
import type { NativeSqlTables } from "./native-sql-table";
import { makeNativePasskeyServices } from "./passkey-native";
import type { PasskeyNativeMapping, PasskeyNativeRead } from "./passkey-native-state";
import {
  makePasskeyNativeManagement,
  type NativePasskeyManagementMapping,
} from "./passkey-native-write";
import { anySqlCondition } from "./sql-change";
import { storageTables, type StorageRole } from "./storage-tables";

export interface ComposedPasskeyInput {
  readonly storage: MappingInput;
  readonly namespace: string;
  readonly dialect: "pg" | "sqlite";
  readonly features: ReadonlyArray<PasskeyFeature>;
  readonly passwordModules: ReadonlyArray<string>;
}

const profileJson = Schema.fromJsonString(M.PasskeyProfile);

const credentialData = M.PasskeyCredential.mapFields(
  ({ revision: _revision, active: _active, requirement: _requirement, ...fields }) => fields,
);

const configurationError = (reason: string) => PersistenceConfigurationError.make({ reason });

const mappings = Effect.fnUntraced(function* (
  storage: MappingInput,
  tables: NativeSqlTables,
  passwordModules: ReadonlyArray<string>,
  signInProfiles: ReadonlyArray<M.PasskeyProfile>,
) {
  const sql = (yield* SqlClient.SqlClient).withoutTransforms();

  const table = (role: StorageRole) => {
    const value = storage.tables[role];

    if (value === undefined) throw configurationError(`Missing ${role} mapping`);

    return value;
  };

  const mapped = <Role extends StorageRole>(role: Role) => ({
    table: table(role),
    // Managed storage validation owns these physical column keys.
    ...(Object.fromEntries(Object.keys(storageTables[role].columns).map((key) => [key, key])) as {
      readonly [Key in keyof (typeof storageTables)[Role]["columns"]]: Key;
    }),
  });

  const t = (role: StorageRole) => tables(table(role));

  const eq = (role: StorageRole, key: string, value: unknown) =>
    sql`${t(role).column(key)} = ${t(role).value(key, value)}`;

  const s = storage.subjects;
  const subject = tables(s.table);
  const active = (value: unknown) => value === true;

  const read: PasskeyNativeRead = {
    subject: {
      table: s.table,
      id: s.id,
      status: s.status,
      securityRevision: s.securityRevision,
      decodeId: (row) => row[s.id],
      decodeRequirement: s.requirements,
      isActiveStatus: (value) => Object.is(value, s.activeValue),
      activeCondition: sql`${subject.column(s.status)} = ${subject.value(s.status, s.activeValue)}`,
    },
    credential: {
      ...mapped("passkeyCredentials"),
      status: "active",
      decode: (row) =>
        Schema.decodeUnknownSync(credentialData)({
          ...row,
          profile: Schema.decodeUnknownSync(profileJson)(row.profile),
        }),
      decodeSubjectId: (row) => row.subjectId,
      isActiveStatus: active,
      activeCondition: eq("passkeyCredentials", "active", true),
    },
    authority: {
      ...mapped("credentials"),
      status: "active",
      isActiveStatus: active,
      activeCondition: eq("credentials", "active", true),
    },
    subjectIds: { toNative: s.toNativeSync, toSubject: s.toSubjectSync, equals: Object.is },
    constraints: requiredPasskeyCredentialConstraints,
  };

  const base = (feature: PasskeyFeature): PasskeyNativeMapping => ({
    moduleId: feature.moduleId,
    read,
    flow: { ...mapped("passkeyFlows"), encodeInsert: () => ({}) },
    clock: {
      encodeInstant: storage.encodeInstant,
      decodeInstant: storage.decodeInstantSync,
      engineNowMillis: sql.onDialectOrElse({
        pg: () => sql`cast(extract(epoch from clock_timestamp()) * 1000 as bigint)`,
        orElse: () => sql`cast(round((julianday('now') - 2440587.5) * 86400000) as integer)`,
      }),
      toMillis: (expression: Fragment) => expression,
      fromMillis: (expression: Fragment) => expression,
    },
    telemetry: {
      lastUsedAt: "lastUsedAt",
      encodeBackupEligible: (value) => value,
      encodeBackupState: (value) => value,
    },
    constraints: requiredPasskeyPersistenceConstraints,
  });

  const metadata = (nativeId: unknown) =>
    sql`exists(select 1 from ${subject.name} where ${subject.column(s.id)} = ${subject.value(s.id, nativeId)} and ${subject.column(s.status)} = ${subject.value(s.status, s.activeValue)})`;

  const management = (feature: PasskeyFeature): NativePasskeyManagementMapping => {
    const policy = feature.managementPolicy;

    if (policy === undefined)
      throw configurationError(`Missing passkey management policy for ${feature.moduleId}`);

    const c = t("passkeyCredentials"),
      f = t("credentials");

    return {
      ...base(feature),
      write: {
        credential: {
          name: "name",
          createdAt: "createdAt",
          encodeInsert: ({ credential, subjectId, summary, marker }) => ({
            credentialId: credential.credentialId,
            subjectId,
            rpId: credential.rpId,
            protocolCredentialId: credential.protocolCredentialId,
            userHandle: credential.userHandle,
            credentialKey: "",
            publicKey: credential.publicKey,
            algorithm: credential.algorithm,
            profile: Schema.encodeSync(profileJson)(credential.profile),
            credentialRevision: marker,
            active: true,
            primarySignIn: credential.primarySignIn,
            enrollmentUserVerified: credential.enrollmentUserVerified,
            backupEligible: credential.backupEligible,
            backupState: credential.backupState,
            counter: credential.counter,
            name: summary.name,
            createdAt: storage.encodeInstant(summary.createdAtMillis),
          }),
          encodePrimarySignIn: (value) => value,
          encodeEnrollmentUserVerified: (value) => value,
          encodeBackupEligible: (value) => value,
          activeStatus: true,
          removedStatus: false,
        },
        authority: {
          encodeInsert: ({ subjectId, credential, marker }) => ({
            subjectId,
            credentialId: credential.credentialId,
            revision: marker,
            active: true,
          }),
          activeStatus: true,
          removedStatus: false,
        },
        policy: {
          subjectColumns: subject.keys,
          management: () => policy,
          requirement: s.actionRequirements,
          metadata,
          action: metadata,
          remainingSignIn: (nativeId, excluded, row) =>
            Effect.gen(function* () {
              const requirement = yield* Schema.decodeEffect(M.PasskeyRequirement)(
                yield* s.requirements(row),
              );

              const alternatives: Fragment[] = [];

              if (
                requirement.alternatives.some(
                  (alternative) =>
                    alternative.minimumCredentials === 1 &&
                    alternative.factors.every((factor) => factor === "possession"),
                )
              ) {
                alternatives.push(sql`exists(select 1 from ${c.name} join ${f.name} on ${f.column("credentialId")} = ${c.column("credentialId")} and ${f.column("subjectId")} = ${f.value("subjectId", nativeId)} and ${f.column("revision")} = ${c.column("credentialRevision")} and ${eq("credentials", "active", true)}
                where ${eq("passkeyCredentials", "subjectId", nativeId)} and ${c.column("credentialId")} <> ${c.value("credentialId", excluded)} and ${eq("passkeyCredentials", "active", true)} and ${eq("passkeyCredentials", "primarySignIn", true)} and ${eq("passkeyCredentials", "enrollmentUserVerified", true)} and ${anySqlCondition(
                  sql,
                  signInProfiles.map((profile) => eq("passkeyCredentials", "rpId", profile.rpId)),
                )})`);
              }
              if (
                passwordModules.length > 0 &&
                requirement.alternatives.some(
                  (alternative) =>
                    alternative.minimumCredentials === 1 &&
                    !alternative.userVerified &&
                    !alternative.phishingResistant &&
                    alternative.factors.every((factor) => factor === "knowledge"),
                )
              ) {
                const p = t("passwords"),
                  i = t("identifiers");

                alternatives.push(sql`exists(select 1 from ${p.name} join ${f.name} on ${f.column("credentialId")} = ${p.column("credentialId")} and ${f.column("subjectId")} = ${f.value("subjectId", nativeId)} and ${f.column("revision")} = ${p.column("credentialRevision")} and ${eq("credentials", "active", true)}
                join ${i.name} on ${eq("identifiers", "subjectId", nativeId)} and ${eq("identifiers", "active", true)} and ${eq("identifiers", "namespace", "email")}
                where ${eq("passwords", "subjectId", nativeId)} and ${p.column("credentialId")} <> ${p.value("credentialId", excluded)} and ${anySqlCondition(
                  sql,
                  passwordModules.map((module) => eq("passwords", "moduleId", module)),
                )})`);
              }

              return anySqlCondition(sql, alternatives);
            }).pipe(
              Effect.mapError((cause) =>
                PersistenceMappingError.make({ operation: "mapping", cause }),
              ),
            ),
        },
      },
      invalidation: {
        window: {
          trigger: "credential-change",
          existingSessions: "immediate",
          maximumExposureMillis: 0,
          oldAuthenticationEvidence: "rejected",
        },
        mutations: [],
        postcondition: ({ subjectId, securityRevision }) =>
          sql`exists(select 1 from ${subject.name} where ${subject.column(s.id)} = ${subject.value(s.id, subjectId)} and ${subject.column(s.securityRevision)} = ${subject.value(s.securityRevision, securityRevision)})`,
      },
    };
  };

  return { base, management };
});

/** Managed and mapped tables feed the same native passkey statements. */
export const makeManagedPasskeys = Effect.fnUntraced(
  function* (input: ComposedPasskeyInput, tables: NativeSqlTables) {
    const policies = yield* Effect.forEach(input.features, (feature) =>
      Effect.map(feature.policy, (policy) => ({ feature, policy })),
    );

    const mapping = yield* mappings(
      input.storage,
      tables,
      input.passwordModules,
      policies.flatMap(({ feature, policy }) => (feature.management ? [] : policy.profiles)),
    );

    const services = new Map<
      string,
      Effect.Success<ReturnType<typeof makeNativePasskeyServices>>
    >();

    const managers = new Map<string, M.PasskeyManagementPersistence["Service"]>();

    for (const feature of input.features) {
      const selected = feature.management ? mapping.management(feature) : mapping.base(feature);
      const base = yield* makeNativePasskeyServices(tables, selected);

      services.set(feature.moduleId, base);
      if (feature.management)
        managers.set(
          feature.moduleId,
          makePasskeyNativeManagement(base, mapping.management(feature))
            .passkeyManagementPersistence,
        );
    }

    const service = (moduleId: string) => {
      const value = services.get(moduleId);

      return value === undefined
        ? Effect.fail(M.PasskeyUnavailable.make({}))
        : Effect.succeed(value);
    };

    const manager = (moduleId: string) => {
      const value = managers.get(moduleId);

      return value === undefined
        ? Effect.fail(M.PasskeyUnavailable.make({}))
        : Effect.succeed(value);
    };

    const first = services.values().next().value;

    if (first === undefined) return yield* configurationError("A passkey module is required");

    let context: Context.Context<never> = Context.make(M.PasskeyCredentials, {
      lookup: (input) => first.passkeyCredentials.lookup(input),
      listForSubject: (input) =>
        Effect.flatMap(service(input.moduleId), (value) =>
          value.passkeyCredentials.listForSubject(input),
        ),
    }).pipe(
      Context.add(M.PasskeyPersistence, {
        issue: (input, prepare) =>
          Effect.flatMap(service(input.ceremony.moduleId), (value) =>
            value.passkeyPersistence.issue(input, prepare),
          ),
        context: (input) =>
          Effect.flatMap(service(input.moduleId), (value) =>
            value.passkeyPersistence.context(input),
          ),
        consume: (input, prepare) =>
          Effect.flatMap(service(input.access.moduleId), (value) =>
            value.passkeyPersistence.consume(input, prepare),
          ),
        cleanup: (input, prepare) =>
          Effect.flatMap(service(input.moduleId), (value) =>
            value.passkeyPersistence.cleanup(input, prepare),
          ),
      }),
    );

    if (managers.size > 0)
      context = context.pipe(
        Context.add(M.PasskeyManagementPersistence, {
          completeEnrollment: (input, prepare) =>
            Effect.flatMap(manager(input.ceremony.moduleId), (value) =>
              value.completeEnrollment(input, prepare),
            ),
          list: (input) => Effect.flatMap(manager(input.moduleId), (value) => value.list(input)),
          inspectRemove: (input) =>
            Effect.flatMap(manager(input.moduleId), (value) => value.inspectRemove(input)),
          rename: (input, prepare) =>
            Effect.flatMap(manager(input.moduleId), (value) => value.rename(input, prepare)),
          remove: (input, prepare) =>
            Effect.flatMap(manager(input.moduleId), (value) => value.remove(input, prepare)),
        }),
      );

    return context;
  },
  Effect.mapError((error) =>
    Schema.is(PersistenceConfigurationError)(error)
      ? error
      : configurationError("Unable to configure passkey persistence"),
  ),
);
