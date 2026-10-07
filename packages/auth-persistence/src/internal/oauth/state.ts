import {
  type OAuthActionAuthorization,
  type OAuthConnectedActionAuthorization,
  type OAuthAccountRevision,
  OAuthUnavailable,
  OAuthExternalIdentity,
  snapshotOAuthSync,
} from "@yielded/auth/OAuth";
import type { AuthenticationRequirement } from "@yielded/auth/Sessions";
import { Crypto, DateTime, Effect, Schema } from "effect";
import { Base64Url } from "effect/encoding";

import { digest, randomId } from "../crypto";
export { digest } from "../crypto";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const unavailable = () => OAuthUnavailable.make({});

export const invariant: (value: unknown) => asserts value = (value) => {
  if (!value) throw unavailable();
};

export const nonce = randomId;

/** Capture configuration/callback references while preserving adapter table, SQL
 * and Effect objects. Never freeze or mutate the consumer's original graph. */
export const captureOAuthMapping = <A>(input: A): A => {
  const seen = new Map<object, unknown>();

  const copy = (value: unknown): unknown => {
    if (value === null || typeof value !== "object" || Effect.isEffect(value)) return value;
    if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype) return value;
    const prior = seen.get(value);

    if (prior !== undefined) return prior;
    if (Array.isArray(value)) {
      const result: unknown[] = [];

      seen.set(value, result);
      result.push(...value.map(copy));

      return Object.freeze(result);
    }
    const result: Record<string, unknown> = {};

    seen.set(value, result);
    for (const [key, child] of Object.entries(value)) result[key] = copy(child);

    return Object.freeze(result);
  };

  return copy(input) as A;
};

/** Versioned length-delimited UTF-8 tuple; the module is deliberately excluded.
 * Reject ill-formed UTF-16 rather than letting UTF-8 replacement alias identities. */
export const oauthIdentityKey = Effect.fnUntraced(function* (
  input: typeof OAuthExternalIdentity.Type,
) {
  const identity = snapshotOAuthSync(OAuthExternalIdentity, input);

  const fields = [
    "effect-auth/oauth-identity-key/v1",
    identity.provider,
    identity.issuer,
    identity.subject,
  ];

  const bytes = fields.map((field) => {
    const value = encoder.encode(field);

    invariant(decoder.decode(value) === field);

    return value;
  });

  const packed = new Uint8Array(bytes.reduce((size, value) => size + 4 + value.length, 0));
  const view = new DataView(packed.buffer);
  let offset = 0;

  for (const value of bytes) {
    view.setUint32(offset, value.length, false);
    packed.set(value, offset + 4);
    offset += 4 + value.length;
  }

  const crypto = yield* Crypto.Crypto;

  return "v1:" + Base64Url.encode(yield* crypto.digest("SHA-256", packed));
});

export const sameIdentity = (
  left: typeof OAuthExternalIdentity.Type,
  right: typeof OAuthExternalIdentity.Type,
) =>
  left.provider === right.provider &&
  left.issuer === right.issuer &&
  left.subject === right.subject;

/** Private Type storage: opaque wrappers and DateTimes are freshly reconstructed. */
export const storage = <S extends Schema.Codec<unknown, unknown, never, never>>(schema: S) => {
  const codec = Schema.fromJsonString(Schema.toCodecJson(Schema.toType(schema)));
  const encode = Schema.encodeSync(codec);
  const decode = Schema.decodeSync(codec);

  return {
    encode: (value: S["Type"]) => encode(snapshotOAuthSync(schema, value)),
    decode: (value: string) => snapshotOAuthSync(schema, decode(value)),
  };
};

export const sameRevision = (left: OAuthAccountRevision, right: OAuthAccountRevision) => {
  if (
    left.subjectId !== right.subjectId ||
    left.securityRevision !== right.securityRevision ||
    left.credentials.length !== right.credentials.length
  )
    return false;
  const revisions = new Map(left.credentials.map((item) => [item.credentialId, item.revision]));

  return (
    revisions.size === left.credentials.length &&
    new Set(right.credentials.map((item) => item.credentialId)).size === right.credentials.length &&
    right.credentials.every((item) => revisions.get(item.credentialId) === item.revision)
  );
};

export const satisfies = (
  proofs: ReadonlyArray<{
    readonly credentialId: string;
    readonly factors: ReadonlyArray<string>;
    readonly userVerified: boolean;
    readonly phishingResistant: boolean;
  }>,
  requirement: AuthenticationRequirement,
) => {
  const factors = new Set(proofs.flatMap((proof) => [...proof.factors]));
  const count = new Set(proofs.map((proof) => proof.credentialId)).size;

  return requirement.alternatives.some(
    (alternative) =>
      alternative.factors.every((factor) => factors.has(factor)) &&
      count >= alternative.minimumCredentials &&
      proofs.some(
        (proof) =>
          (!alternative.userVerified || proof.userVerified) &&
          (!alternative.phishingResistant || proof.phishingResistant),
      ),
  );
};

export const validAction = Effect.fnUntraced(function* (
  authorization: OAuthActionAuthorization | OAuthConnectedActionAuthorization,
  expected: {
    readonly moduleId: string;
    readonly action:
      | OAuthActionAuthorization["challenge"]["action"]
      | OAuthConnectedActionAuthorization["challenge"]["action"];
    readonly flowId: string;
    readonly revision: OAuthAccountRevision;
    readonly intent: string;
  },
  currentRequirement: AuthenticationRequirement,
  now: number,
  maximumAgeMillis: number,
) {
  const challenge = authorization.challenge;
  const evidence = authorization.evidence;
  const intentDigest = yield* digest(expected.intent);

  const binding = yield* digest(
    // oxlint-disable-next-line no-restricted-properties -- Fixed private action fingerprint format shared with the core verifier.
    JSON.stringify([
      expected.action.startsWith("connected-")
        ? "effect-auth/oauth-connected-action/v1"
        : "effect-auth/oauth-action/v1",
      expected.moduleId,
      expected.action,
      expected.flowId,
      intentDigest,
    ]),
  );

  if (
    now >= authorization.validUntilMillis ||
    challenge.moduleId !== expected.moduleId ||
    challenge.action !== expected.action ||
    challenge.flowId !== expected.flowId ||
    challenge.intentDigest !== intentDigest ||
    challenge.bindingDigest !== binding ||
    evidence.flowId !== expected.flowId ||
    evidence.bindingDigest !== binding ||
    !sameRevision(challenge.revision, expected.revision) ||
    !sameRevision(evidence.revision, expected.revision)
  )
    return false;

  const revisions = new Map(
    expected.revision.credentials.map((item) => [item.credentialId, item.revision]),
  );

  if (
    evidence.proofs.some(
      (proof) =>
        !revisions.has(proof.credentialId) || DateTime.toEpochMillis(proof.verifiedAt) > now,
    )
  )
    return false;

  if (authorization.source._tag === "Session") {
    const authenticatedAt = DateTime.toEpochMillis(authorization.source.authenticatedAt);

    if (
      authenticatedAt > now ||
      now - authenticatedAt >=
        Math.min(maximumAgeMillis, authorization.requirement.maximumAgeMillis)
    )
      return false;
  }

  return [authorization.requirement, currentRequirement].every((requirement) => {
    const fresh = evidence.proofs.filter((proof) => {
      const age = now - DateTime.toEpochMillis(proof.verifiedAt);

      return age >= 0 && age < Math.min(maximumAgeMillis, requirement.maximumAgeMillis);
    });

    return satisfies(fresh, requirement);
  });
});
