import { Predicate, Schema } from "effect";

// These are mapping contracts, not a parser for arbitrary constraint declarations.
// Role aliases are explicit because their documentation names differ from mapping fields.
const uniquePlans: Readonly<Record<string, readonly [string, ReadonlyArray<string>]>> = {
  "unique(authority.subjectId,authority.credentialId)": [
    "authority",
    ["subjectId", "credentialId"],
  ],
  "unique(authorityCredential.subjectId,authorityCredential.credentialId)": [
    "authorityCredential",
    ["subjectId", "credentialId"],
  ],
  "unique(connectedGrant.moduleId,connectedGrant.grantId)": ["grant", ["moduleId", "grantId"]],
  "unique(connectedGrant.moduleId,connectedGrant.subjectId,connectedGrant.profileKey,connectedGrant.identityKey)":
    ["grant", ["moduleId", "subjectId", "profileKey", "identityKey"]],
  "unique(connectedRevocation.jobId)": ["job", ["jobId"]],
  "unique(credential.credentialId)": ["credential", ["credentialId"]],
  "unique(credential.identityKey)": ["credential", ["identityKey"]],
  "unique(credential.moduleId,credential.credentialId)": [
    "credential",
    ["moduleId", "credentialId"],
  ],
  "unique(credential.moduleId,credential.subjectId)": ["credential", ["moduleId", "subjectId"]],
  "unique(emailCredential.moduleId,emailCredential.credentialId)": [
    "credential",
    ["moduleId", "credentialId"],
  ],
  "unique(emailCredential.moduleId,emailCredential.identifierNamespace,emailCredential.identifierValue)":
    ["credential", ["moduleId", "identifierNamespace", "identifierValue"]],
  "unique(flow.moduleId,flow.flowId)": ["flow", ["moduleId", "flowId"]],
  "unique(flow.stateDigest)": ["flow", ["stateDigest"]],
  "unique(identifier.namespace,identifier.value)": ["identifier", ["namespace", "value"]],
  "unique(intent.moduleId,intent.flowId)": ["intent", ["moduleId", "flowId"]],
  "unique(intent.moduleId,intent.reference)": ["intent", ["moduleId", "reference"]],
  "unique(ownership.identityKey)": ["ownership", ["identityKey"]],
  "unique(proof.moduleId,proof.purpose,proof.seriesKey)": [
    "proof",
    ["moduleId", "purpose", "seriesKey"],
  ],
  "unique(proof.moduleId,proof.proofId)": ["proof", ["moduleId", "proofId"]],
  "unique(pending.digest)": ["pending", ["digest"]],
  "unique(session.digest)": ["session", ["digest"]],
  "unique(tombstone.moduleId,tombstone.subjectId,tombstone.sessionId)": [
    "tombstone",
    ["moduleId", "subjectId", "sessionId"],
  ],
};

const arrayRoles: Readonly<Record<string, string>> = {
  credentialId: "credential",
  credentialKey: "credential",
  factor: "authority",
  flow: "flow",
};

const nestedMappings = [
  "read",
  "signIn",
  "password",
  "proof",
  "proofs",
  "revocation",
  "pending",
  "session",
  "source",
];

const constraintGroups = ["constraints"];

const MappingRecord = Schema.Record(Schema.String, Schema.Unknown);
const record = Schema.decodeUnknownSync(MappingRecord);

export const storageKeyPlans = (
  input: unknown,
  columnsFor: (table: object) => Readonly<Record<string, unknown>>,
) => {
  const mapping = record(input);
  const result: Array<{ readonly table: object; readonly keys: ReadonlyArray<string> }> = [];

  for (const group of constraintGroups) {
    if (mapping[group] === undefined) continue;
    for (const [name, declaration] of Object.entries(record(mapping[group]))) {
      if (declaration === "notNull(provisioningRequest.subjectId)") continue;
      let role: string;
      let keys: ReadonlyArray<string>;

      if (typeof declaration === "string") {
        const plan = uniquePlans[declaration];

        if (plan !== undefined) [role, keys] = plan;
        else if (declaration === "unique(id)") {
          role = "subject";
          keys = ["id"];
        } else if (declaration === "unique(scope)") {
          role = name;
          keys = ["scope"];
        } else if (declaration === "unique(credentialId)") {
          role = "credential";
          keys = ["id"];
        } else if (declaration === "unique(namespace,value)") {
          role = "identifier";
          keys = ["namespace", "value"];
        } else if (declaration === "unique(provider,issuer,subject)") {
          role = "externalIdentity";
          keys = ["provider", "issuer", "subject"];
        } else if (declaration === "unique(requestId)") {
          role = "provisioningRequest";
          keys = ["requestId"];
        } else throw new Error("Unknown storage constraint");
      } else if (Array.isArray(declaration) && declaration.every(Predicate.isString)) {
        const mappedRole = arrayRoles[name];

        if (mappedRole === undefined) throw new Error("Unknown storage constraint");
        role = mappedRole;
        keys = declaration;
      } else throw new Error("Invalid storage constraint");

      let target: unknown = mapping;

      for (const segment of role.split(".")) target = record(target)[segment];
      // Session authority places its pending tables in one nested mapping.
      if (target === undefined && Schema.is(MappingRecord)(mapping.pending))
        target = mapping.pending[role];
      let mapped = record(target);

      if (role === "pending" && mapped.table === undefined) mapped = record(mapped.pending);
      if (!Predicate.isObject(mapped.table)) throw new Error("Missing storage table");
      const columns = columnsFor(mapped.table);

      result.push({
        table: mapped.table,
        keys: keys.map((key) => {
          const value = mapped[key];

          if (typeof value !== "string" || columns[value] === undefined)
            throw new Error("Missing mapped key");

          return value;
        }),
      });
    }
  }
  for (const nested of nestedMappings) {
    const value = mapping[nested];

    if (Schema.is(MappingRecord)(value) && value.table === undefined)
      result.push(...storageKeyPlans(value, columnsFor));
  }

  return result;
};
