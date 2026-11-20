import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import * as OAuthError from "../OAuthError.ts";

export const invalidArgument = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.InvalidArgument({ description, cause }),
  });

const knownOAuthErrorCodes: ReadonlySet<string> = new Set<OAuthError.OAuthErrorCode>([
  "invalid_request",
  "invalid_client",
  "invalid_grant",
  "unauthorized_client",
  "unsupported_grant_type",
  "unsupported_response_type",
  "unsupported_token_type",
  "invalid_scope",
  "invalid_target",
  "invalid_token",
  "insufficient_scope",
  "access_denied",
  "interaction_required",
  "login_required",
  "account_selection_required",
  "consent_required",
  "temporarily_unavailable",
  "server_error",
]);

export const normalizeOAuthErrorCode = (
  value: string,
): { readonly code: OAuthError.OAuthErrorCode; readonly rawCode?: string | undefined } =>
  knownOAuthErrorCodes.has(value)
    ? { code: value as OAuthError.OAuthErrorCode }
    : { code: "other", rawCode: value };

export const text = (maximum: number) => Schema.NonEmptyString.check(Schema.isMaxLength(maximum));

export const integer = (minimum: number, maximum: number) =>
  Schema.Int.check(Schema.isBetween({ minimum, maximum }));

export const secret = (maximum: number) =>
  Schema.Redacted(text(maximum), { disallowJsonEncode: true });

const forbiddenJsonKeys: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);
const maxJsonDepth = 64;
const maxJsonValues = 65536;

const defineDataProperty = (
  target: Record<string, Schema.Json>,
  key: string,
  value: Schema.Json,
): void => {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
};

const isCanonicalArrayIndex = (key: string, length: number): boolean => {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(key)) return false;
  const index = Number(key);

  return index >= 0 && index < length;
};

// Single descriptor-only plain JSON walker: never invokes getters, enforces
// plain Object/Array prototypes, canonical array indices without expando
// properties, max depth 64, and max 65,536 values. When `rejectForbiddenKeys`
// is true, also rejects `__proto__`, `constructor`, and `prototype`. When
// `copy` is false, validates in place without allocating clones.
function walkPlainJsonObject(
  root: unknown,
  copy: true,
  rejectForbiddenKeys: boolean,
): Record<string, Schema.Json> | undefined;
function walkPlainJsonObject(root: unknown, copy: false, rejectForbiddenKeys: boolean): boolean;
function walkPlainJsonObject(
  root: unknown,
  copy: boolean,
  rejectForbiddenKeys: boolean,
): Record<string, Schema.Json> | boolean | undefined {
  if (root === null || typeof root !== "object" || Array.isArray(root)) {
    return copy ? undefined : false;
  }

  const rootPrototype = Object.getPrototypeOf(root);

  if (rootPrototype !== Object.prototype && rootPrototype !== null) {
    return copy ? undefined : false;
  }

  const result: Record<string, Schema.Json> | undefined = copy ? {} : undefined;

  const pending: Array<
    | {
        readonly kind: "object";
        readonly source: object;
        readonly target: Record<string, Schema.Json> | undefined;
        readonly depth: number;
      }
    | {
        readonly kind: "array";
        readonly source: ReadonlyArray<unknown>;
        readonly target: Array<Schema.Json> | undefined;
        readonly depth: number;
      }
  > = [{ kind: "object", source: root, target: result, depth: 1 }];

  let values = 1;

  const enqueue = (
    value: unknown,
    depth: number,
  ): { readonly ok: true; readonly value: Schema.Json | undefined } | { readonly ok: false } => {
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "boolean" ||
      (typeof value === "number" && Number.isFinite(value))
    ) {
      return { ok: true, value };
    }

    if (typeof value !== "object") return { ok: false };

    const nextDepth = depth + 1;

    if (nextDepth > maxJsonDepth) return { ok: false };

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return { ok: false };
      const target: Array<Schema.Json> | undefined = copy ? [] : undefined;

      pending.push({ kind: "array", source: value, target, depth: nextDepth });

      return { ok: true, value: target };
    }

    const prototype = Object.getPrototypeOf(value);

    if (prototype !== Object.prototype && prototype !== null) return { ok: false };
    const target: Record<string, Schema.Json> | undefined = copy ? {} : undefined;

    pending.push({ kind: "object", source: value, target, depth: nextDepth });

    return { ok: true, value: target };
  };

  for (let frame = pending.pop(); frame !== undefined; frame = pending.pop()) {
    if (frame.kind === "array") {
      const lengthDescriptor = Object.getOwnPropertyDescriptor(frame.source, "length");

      if (
        lengthDescriptor === undefined ||
        !("value" in lengthDescriptor) ||
        typeof lengthDescriptor.value !== "number" ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0
      ) {
        return copy ? undefined : false;
      }

      const length = lengthDescriptor.value;

      values += length;
      if (values > maxJsonValues) return copy ? undefined : false;

      const keys = Reflect.ownKeys(frame.source);

      if (keys.length !== length + 1) return copy ? undefined : false;

      for (const key of keys) {
        if (typeof key !== "string") return copy ? undefined : false;
        if (key !== "length" && !isCanonicalArrayIndex(key, length)) {
          return copy ? undefined : false;
        }
      }

      for (let index = 0; index < length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(frame.source, String(index));

        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          return copy ? undefined : false;
        }

        const child = enqueue(descriptor.value, frame.depth);

        if (!child.ok) return copy ? undefined : false;
        if (frame.target !== undefined && child.value !== undefined) frame.target.push(child.value);
      }

      continue;
    }

    const keys = Reflect.ownKeys(frame.source);

    values += keys.length;
    if (values > maxJsonValues) return copy ? undefined : false;

    for (const key of keys) {
      if (typeof key !== "string" || (rejectForbiddenKeys && forbiddenJsonKeys.has(key))) {
        return copy ? undefined : false;
      }

      const descriptor = Object.getOwnPropertyDescriptor(frame.source, key);

      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        return copy ? undefined : false;
      }

      const child = enqueue(descriptor.value, frame.depth);

      if (!child.ok) return copy ? undefined : false;
      if (frame.target !== undefined && child.value !== undefined) {
        defineDataProperty(frame.target, key, child.value);
      }
    }
  }

  return copy ? result : true;
}

export const hasSafeJsonGraph = (root: unknown): boolean => walkPlainJsonObject(root, false, true);

export const snapshotPlainJson = (
  input: unknown,
  onError: () => OAuthError.OAuthError,
): Effect.Effect<Record<string, Schema.Json>, OAuthError.OAuthError> =>
  Effect.try({
    try: () => walkPlainJsonObject(input, true, true),
    catch: onError,
  }).pipe(
    Effect.filterOrFail(
      (snapshot): snapshot is Record<string, Schema.Json> => snapshot !== undefined,
      onError,
    ),
  );

/** At most 64 nested containers and 65,536 values, including the root object. */
export const JsonObject = Schema.Record(Schema.String, Schema.Json).check(
  Schema.makeFilter((value) => walkPlainJsonObject(value, false, false)),
);

/** HTTPS, or HTTP on an exact loopback host for local development. */
const validUrl = (value: string) => {
  try {
    const url = new URL(value);

    return (
      (url.protocol === "https:" ||
        (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) &&
      url.username === "" &&
      url.password === "" &&
      !value.includes("#") &&
      // oxlint-disable-next-line no-control-regex -- Reject URL parser normalization of untrusted controls.
      !/[\s\\\u0000-\u001f\u007f]/u.test(value)
    );
  } catch {
    return false;
  }
};

export const Endpoint = text(2048).check(Schema.makeFilter((value) => validUrl(value)));

export const endpointMatchesIssuer = (issuer: string, endpoint: string) =>
  new URL(endpoint).protocol === "https:" || new URL(issuer).protocol === "http:";

export const Issuer = Endpoint.check(
  Schema.makeFilter(
    (value) => !value.includes("?") && !new URL(value).pathname.includes("/.well-known/"),
  ),
);

export const Callback = text(2048).check(
  Schema.makeFilter(
    (value) => validUrl(value) && new URL(value).href === value && !value.includes("?"),
  ),
);

// oxlint-disable-next-line no-control-regex -- RFC6749 scope-token permits these visible ASCII ranges.
export const ScopeName = Schema.String.check(Schema.isPattern(/^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/));

export const Scopes = Schema.Array(ScopeName).check(
  Schema.isMaxLength(64),
  Schema.makeFilter((values) => new Set(values).size === values.length),
);

export const Resource = text(2048).check(
  Schema.makeFilter((value) => {
    try {
      const url = new URL(value);

      return (
        // oxlint-disable-next-line no-control-regex -- Preserve exact resource identifiers.
        url.username === "" && url.password === "" && !/[\s\\#\u0000-\u001f\u007f]/u.test(value)
      );
    } catch {
      return false;
    }
  }),
);

export const Resources = Schema.Array(Resource).check(Schema.isMaxLength(64));

export const RequestOptions = Schema.Struct({
  timeoutMs: Schema.Finite.check(Schema.isBetween({ minimum: 1, maximum: 60000 })),
  maxResponseBytes: integer(1, 1048576).pipe(
    Schema.withDecodingDefaultKey(Effect.succeed(1048576)),
  ),
});

export const Verifier = Schema.Redacted(
  Schema.String.check(Schema.isPattern(/^[A-Za-z0-9._~-]{43,128}$/)),
  { disallowJsonEncode: true },
);

export const Challenge = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/));

export const NumericDate = Schema.Finite.check(
  Schema.isBetween({ minimum: 0, maximum: 8640000000000 }),
);

export const reserved = new Set([
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
  "redirect_uri",
  "response_type",
  "response_mode",
  "state",
  "code",
  "code_verifier",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "scope",
  "iss",
  "grant_type",
  "refresh_token",
  "token",
  "token_type_hint",
  "max_age",
  "request",
  "request_uri",
  "authorization_details",
  "id_token_hint",
  "login_hint",
  "login_hint_token",
  "subject_token",
  "subject_token_type",
  "actor_token",
  "actor_token_type",
  "requested_token_type",
]);

export const Parameters = Schema.Record(
  Schema.String.check(Schema.isPattern(/^[A-Za-z][A-Za-z0-9._~-]{0,63}$/)),
  Schema.String.check(Schema.isMaxLength(2048)),
).check(
  Schema.makeFilter(
    (value) =>
      Object.keys(value).length <= 16 &&
      Object.keys(value).every((key) => !reserved.has(key.toLowerCase())),
  ),
);

export const ProtocolEndpoint = Endpoint.check(
  Schema.makeFilter((value) =>
    Array.from(new URL(value).searchParams.keys()).every((key) => !reserved.has(key.toLowerCase())),
  ),
);

// Keep exceptions from hostile input access and erased Redacted values inside
// schema decoding; service execution must remain outside these catches.
export const configuration = <S extends Schema.Constraint>(
  schema: S,
  input: unknown,
  description = "Invalid OAuth configuration or parameters",
) =>
  Effect.suspend(() => Schema.decodeUnknownEffect(schema)(input, { reportInput: false })).pipe(
    Effect.mapError(() => invalidArgument(description)),
    Effect.catchDefect(() => Effect.fail(invalidArgument(description))),
  );

export const decode = <S extends Schema.Constraint>(
  schema: S,
  input: unknown,
  onError: () => OAuthError.OAuthError = () => invalidArgument("Invalid OAuth input"),
) =>
  Effect.suspend(() => Schema.decodeUnknownEffect(schema)(input, { reportInput: false })).pipe(
    Effect.mapError(onError),
    Effect.catchDefect(() => Effect.fail(onError())),
  );

export const reveal = <A>(
  value: Redacted.Redacted<A>,
  onError: () => OAuthError.OAuthError = () =>
    invalidArgument("Redacted OAuth value is unavailable"),
) => Effect.try({ try: () => Redacted.value(value), catch: onError });

export const isWellFormedUnicode = (value: string): boolean => {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);

    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);

      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }

  return true;
};

export const revealString = (
  value: string | Redacted.Redacted<string>,
  onUnavailable: () => OAuthError.OAuthError,
  onInvalid: () => OAuthError.OAuthError = onUnavailable,
): Effect.Effect<string, OAuthError.OAuthError> =>
  Redacted.isRedacted(value)
    ? reveal(value, onUnavailable).pipe(
        Effect.filterOrFail((item): item is string => typeof item === "string", onInvalid),
      )
    : typeof value === "string"
      ? Effect.succeed(value)
      : Effect.fail(onInvalid());

export const Bearer = Schema.Redacted(
  text(16384).check(Schema.isPattern(/^[A-Za-z0-9._~+/-]+=*$/u)),
  { disallowJsonEncode: true },
);

export const isHttpsUrl = (value: string): boolean => {
  try {
    const url = new URL(value);

    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      !value.includes("#") &&
      // oxlint-disable-next-line no-control-regex -- Reject URL parser normalization of untrusted controls.
      !/[\s\\\u0000-\u001f\u007f]/u.test(value)
    );
  } catch {
    return false;
  }
};

// `Duration` reads NaN as zero in every input form, and non-finite or
// overflowing object components add up to NaN. Reject them eagerly.
const hasInvalidDurationComponent = (input: Duration.Input): boolean => {
  if (typeof input === "number") return Number.isNaN(input);
  if (typeof input !== "object" || input === null || Duration.isDuration(input)) return false;
  if (Array.isArray(input)) return input.some((component) => !Number.isFinite(component));

  return Object.entries(input).some(
    ([unit, component]) =>
      typeof component === "number" &&
      (!Number.isFinite(component) || !Number.isFinite(Duration.toMillis({ [unit]: component }))),
  );
};

const durationFromInput = (input: Duration.Input): Option.Option<Duration.Duration> =>
  hasInvalidDurationComponent(input) ? Option.none() : Duration.fromInput(input);

const durationMillis = (input: Duration.Input): Option.Option<number> =>
  Option.map(durationFromInput(input), Duration.toMillis);

export const finiteMillis = (
  name: string,
  input: Duration.Input,
): Effect.Effect<number, OAuthError.OAuthError> => {
  const value = durationMillis(input);

  return Option.isSome(value) && Number.isFinite(value.value) && value.value >= 0
    ? Effect.succeed(value.value)
    : Effect.fail(invalidArgument(`${name} must be a finite, non-negative duration`));
};

export const positiveFiniteMillis = (
  name: string,
  input: Duration.Input,
): Effect.Effect<number, OAuthError.OAuthError> => {
  const value = durationMillis(input);

  return Option.isSome(value) && Number.isFinite(value.value) && value.value > 0
    ? Effect.succeed(value.value)
    : Effect.fail(invalidArgument(`${name} must be a finite, positive duration`));
};

export const positiveMillisOrInfinity = (
  name: string,
  input: Duration.Input,
): Effect.Effect<number, OAuthError.OAuthError> => {
  const value = durationMillis(input);

  return Option.isSome(value) && !Number.isNaN(value.value) && value.value > 0
    ? Effect.succeed(value.value)
    : Effect.fail(invalidArgument(`${name} must be a positive duration or Infinity`));
};

export const wholeSeconds = (
  name: string,
  input: Duration.Input,
): Effect.Effect<number, OAuthError.OAuthError> => {
  const duration = durationFromInput(input);

  if (Option.isNone(duration)) {
    return Effect.fail(
      invalidArgument(`${name} must be a finite, non-negative whole-second duration`),
    );
  }

  const millis = Duration.toMillis(duration.value);
  const nanos = Duration.toNanos(duration.value);

  if (
    !Number.isFinite(millis) ||
    millis < 0 ||
    Option.isNone(nanos) ||
    nanos.value < 0n ||
    nanos.value % 1_000_000_000n !== 0n
  ) {
    return Effect.fail(
      invalidArgument(`${name} must be a finite, non-negative whole-second duration`),
    );
  }

  const seconds = millis / 1000;

  return Number.isSafeInteger(seconds)
    ? Effect.succeed(seconds)
    : Effect.fail(invalidArgument(`${name} must be a finite, non-negative whole-second duration`));
};

export const positiveInteger = (
  name: string,
  value: number,
): Effect.Effect<number, OAuthError.OAuthError> =>
  Number.isSafeInteger(value) && value > 0
    ? Effect.succeed(value)
    : Effect.fail(invalidArgument(`${name} must be a positive integer`));

/** Freeze owned configuration snapshots or freshly parsed wire JSON, not caller-owned graphs. */
export const freeze = <A>(value: A): A => {
  const pending: Array<unknown> = [value];
  const seen = new WeakSet<object>();

  while (pending.length > 0) {
    const item = pending.pop();

    if (!Predicate.isObjectOrArray(item) || Redacted.isRedacted(item) || seen.has(item)) continue;
    seen.add(item);
    for (const child of Object.values(item)) pending.push(child);
    Object.freeze(item);
  }

  return value;
};
