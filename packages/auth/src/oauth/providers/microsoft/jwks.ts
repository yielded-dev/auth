import * as OAuthError from "@yielded/oauth/OAuthError";
import type * as Oidc from "@yielded/oauth/Oidc";
import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as JoseError from "effect/jose/JoseError";
import * as Jwk from "effect/jose/Jwk";
import * as Jwks from "effect/jose/Jwks";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as Tracer from "effect/Tracer";

import { entraTenantId, isTenantIssuerTemplate, substituteTenantIssuer } from "./discovery";

const Issuers = Schema.Struct({
  keys: Schema.Array(
    Schema.Struct({
      issuer: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(2048))),
    }),
  ).check(Schema.isMaxLength(64)),
});

const TenantClaim = Schema.Struct({ tid: entraTenantId });

const keyId = Schema.encodeSync(Schema.fromJsonString(Jwk.PublicJwk));

const forbiddenKeys: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

const defaultTimeToLiveMs = 10 * 60 * 1000;
const defaultCooldownMs = 30 * 1000;
const defaultMaxResponseBytes = 1_048_576;
const defaultMaxKeys = 64;

const hasSafeKeys = (root: unknown): boolean => {
  if (root === null || typeof root !== "object") return false;

  const pending: Array<{ readonly value: object; readonly depth: number }> = [
    { value: root, depth: 1 },
  ];

  let visited = 1;

  for (let frame = pending.pop(); frame !== undefined; frame = pending.pop()) {
    if (frame.depth > 64) return false;
    if (Array.isArray(frame.value)) {
      visited += frame.value.length;
      if (visited > 65536) return false;
      for (const item of frame.value) {
        if (item !== null && typeof item === "object") {
          pending.push({ value: item, depth: frame.depth + 1 });
        }
      }
      continue;
    }

    const keys = Reflect.ownKeys(frame.value);

    visited += keys.length;
    if (visited > 65536) return false;
    for (const key of keys) {
      if (typeof key !== "string" || forbiddenKeys.has(key)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(frame.value, key);

      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        return false;
      }
      if (descriptor.value !== null && typeof descriptor.value === "object") {
        pending.push({ value: descriptor.value, depth: frame.depth + 1 });
      }
    }
  }

  return true;
};

const issuerFailed = (): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.TokenVerificationFailed({ reason: "issuer" }),
  });

const invalidArgument = (description: string): JoseError.JoseError =>
  new JoseError.JoseError({ reason: new JoseError.InvalidArgument({ description }) });

const keySetUnavailable = (description: string, cause?: unknown): JoseError.JoseError =>
  new JoseError.JoseError({
    reason: new JoseError.KeySetUnavailable({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const parseHttpsUrl = (value: string): URL | undefined => {
  try {
    const url = new URL(value);

    return url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      !value.includes("#") &&
      // oxlint-disable-next-line no-control-regex -- Reject URL parser normalization of untrusted controls.
      !/[\s\\\u0000-\u001f\u007f]/u.test(value)
      ? url
      : undefined;
  } catch {
    return undefined;
  }
};

export interface SigningKeyAuthority {
  readonly issuer: string | undefined;
}

interface KeySetSnapshot {
  readonly local: Jwks.Jwks["Service"];
  readonly issuers: ReadonlyMap<string, string | undefined>;
  readonly expiresAt: number;
}

/** Per-key `issuer` JWKS resolver over `effect/jose/Jwks`.
 * Publishes each fetched key set and its per-key `issuer` extensions together
 * as one immutable snapshot so concurrent lookups and key rotations can never
 * pair a key from one document with issuer metadata from another. */
export const makeEntraJwks = Effect.fnUntraced(function* (options: {
  readonly url: string;
  readonly timeoutMs: number;
  readonly maxResponseBytes?: number | undefined;
}) {
  const url = parseHttpsUrl(options.url);

  if (url === undefined) {
    return yield* invalidArgument("url must be an HTTPS URL without credentials or a fragment");
  }

  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
    return yield* invalidArgument("timeoutMs must be a finite positive number");
  }

  const maxResponseBytes = options.maxResponseBytes ?? defaultMaxResponseBytes;

  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    return yield* invalidArgument("maxResponseBytes must be a positive integer");
  }

  const baseHttp = yield* HttpClient.HttpClient;
  const fetch = yield* FetchHttpClient.Fetch;
  const scope = yield* Effect.scope;
  const authorities = new WeakMap<Jwk.PublicKey, SigningKeyAuthority>();

  let cache: KeySetSnapshot | undefined;
  let pending: Deferred.Deferred<KeySetSnapshot, JoseError.JoseError> | undefined;
  let lastAttempt = -Infinity;
  let lastFailed = false;
  let closed = false;

  const closedExit = Exit.fail(keySetUnavailable("The key set scope is closed"));

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      closed = true;
      if (pending !== undefined) Deferred.doneUnsafe(pending, closedExit);
    }),
  );

  const fetchSnapshot: Effect.Effect<KeySetSnapshot, JoseError.JoseError> = Effect.gen(
    function* () {
      const request = HttpClientRequest.get(url.href).pipe(HttpClientRequest.acceptJson);
      const response = yield* HttpClient.withScope(baseHttp).execute(request);

      if (
        response.url !== url.href ||
        response.status !== 200 ||
        response.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !==
          "application/json"
      ) {
        return yield* keySetUnavailable("The key set response was rejected");
      }

      const announced = response.headers["content-length"];

      if (
        announced !== undefined &&
        (!/^\d+$/u.test(announced) || Number(announced) > maxResponseBytes)
      ) {
        return yield* keySetUnavailable(`The key set response exceeds ${maxResponseBytes} bytes`);
      }

      const buffer = new Uint8Array(maxResponseBytes);

      const length = yield* Stream.runFoldEffect(
        response.stream,
        () => 0,
        (offset, chunk) => {
          if (chunk.byteLength > buffer.length - offset) {
            return Effect.fail(
              keySetUnavailable(`The key set response exceeds ${maxResponseBytes} bytes`),
            );
          }
          buffer.set(chunk, offset);

          return Effect.succeed(offset + chunk.byteLength);
        },
      );

      const text = yield* Effect.try({
        try: () => new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, length)),
        catch: () => keySetUnavailable("The key set response is not valid UTF-8"),
      });

      const body = yield* Schema.decodeEffect(Schema.fromJsonString(Schema.Unknown))(text, {
        reportInput: false,
      }).pipe(Effect.mapError(() => keySetUnavailable("The key set document is invalid")));

      if (!hasSafeKeys(body)) {
        return yield* keySetUnavailable("The key set document contains forbidden keys");
      }

      const extensions = yield* Schema.decodeUnknownEffect(Issuers)(body, {
        reportInput: false,
      }).pipe(Effect.mapError(() => keySetUnavailable("The key set issuer metadata is invalid")));

      const keySet = yield* Schema.decodeUnknownEffect(Jwks.KeySet)(body, {
        reportInput: false,
      }).pipe(Effect.mapError(() => keySetUnavailable("The key set document is invalid")));

      if (keySet.keys.length > defaultMaxKeys) {
        return yield* keySetUnavailable(`The key set has more than ${defaultMaxKeys} keys`);
      }

      const issuers = new Map<string, string | undefined>();

      for (const [index, key] of keySet.keys.entries()) {
        if (Schema.is(Jwk.PublicJwk)(key)) {
          const id = keyId(key);
          const keyIssuer = extensions.keys[index]?.issuer;

          if (issuers.has(id) && issuers.get(id) !== keyIssuer) {
            return yield* keySetUnavailable(
              "The key set contains conflicting issuer metadata for the same key",
            );
          }
          issuers.set(id, keyIssuer);
        }
      }

      const local = yield* Jwks.makeLocal(keySet);
      const now = yield* Clock.currentTimeMillis;

      return { local, issuers, expiresAt: now + defaultTimeToLiveMs };
    },
  ).pipe(
    Effect.scoped,
    Effect.provideService(FetchHttpClient.Fetch, fetch),
    Effect.provideService(FetchHttpClient.RequestInit, {
      redirect: "manual",
      credentials: "omit",
      cache: "no-store",
    }),
    Effect.provideService(Tracer.DisablePropagation, true),
    Effect.timeoutOrElse({
      duration: options.timeoutMs,
      orElse: () => Effect.fail(keySetUnavailable("The key set request timed out")),
    }),
    Effect.catchCause((cause) =>
      Effect.failCause(
        Cause.map(cause, (error) =>
          JoseError.isJoseError(error)
            ? error
            : keySetUnavailable("The key set request failed", error),
        ),
      ),
    ),
  );

  const refresh = (
    now: number,
    stale?: KeySetSnapshot,
  ): Effect.Effect<KeySetSnapshot | null, JoseError.JoseError> =>
    Effect.uninterruptibleMask((restore) =>
      Effect.suspend((): Effect.Effect<KeySetSnapshot | null, JoseError.JoseError> => {
        if (closed) return closedExit;
        if (cache !== undefined && cache !== stale && cache.expiresAt > now) {
          return Effect.succeed(cache);
        }
        if (pending !== undefined) return restore(Deferred.await(pending));
        if ((stale !== undefined || lastFailed) && now - lastAttempt < defaultCooldownMs) {
          return Effect.succeed(null);
        }

        lastAttempt = now;
        const result = (pending = Deferred.makeUnsafe<KeySetSnapshot, JoseError.JoseError>());

        const settle = (exit: Exit.Exit<KeySetSnapshot, JoseError.JoseError>) => {
          if (pending === result) {
            pending = undefined;
            lastFailed = Exit.isFailure(exit);
            if (Exit.isSuccess(exit)) cache = exit.value;
          }
          Deferred.doneUnsafe(
            result,
            Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause) ? closedExit : exit,
          );
        };

        return fetchSnapshot.pipe(
          Effect.onExit((exit) => Effect.sync(() => settle(exit))),
          Effect.forkIn(scope, { uninterruptible: false }),
          Effect.tap((fiber) => Effect.sync(() => fiber.addObserver(settle))),
          Effect.andThen(restore(Deferred.await(result))),
        );
      }),
    );

  const lookupInSnapshot = (
    snapshot: KeySetSnapshot,
    selection: Jwks.Selection,
  ): Effect.Effect<Jwk.PublicKey, JoseError.JoseError> =>
    snapshot.local.resolve(selection).pipe(
      Effect.flatMap((key) => {
        const id = keyId(key.jwk);

        if (!snapshot.issuers.has(id)) {
          return Effect.fail(
            keySetUnavailable("Selected signing key has no recorded issuer metadata"),
          );
        }

        const selected: Jwk.PublicKey = { ...key };

        authorities.set(selected, { issuer: snapshot.issuers.get(id) });

        return Effect.succeed(selected);
      }),
    );

  const resolve = (selection: Jwks.Selection): Effect.Effect<Jwk.PublicKey, JoseError.JoseError> =>
    Effect.flatMap(Clock.currentTimeMillis, (now) => {
      if (closed) return closedExit;
      const current = cache;

      if (current !== undefined && current.expiresAt > now) {
        return lookupInSnapshot(current, selection).pipe(
          Effect.catchCause((cause) => {
            const failure = Cause.squash(cause);

            if (!JoseError.isJoseError(failure) || failure.reason._tag !== "KeyNotFound") {
              return Effect.failCause(cause);
            }

            // An unknown key may have been rotated in. Refetch unless cooling down.
            return Effect.flatMap(refresh(now, current), (next) =>
              next === null
                ? Effect.fail(new JoseError.JoseError({ reason: new JoseError.KeyNotFound() }))
                : lookupInSnapshot(next, selection),
            );
          }),
        );
      }

      return Effect.flatMap(refresh(now), (snapshot) =>
        snapshot === null
          ? Effect.fail(keySetUnavailable("The key set is cooling down after a failed fetch"))
          : lookupInSnapshot(snapshot, selection),
      );
    });

  return {
    service: Jwks.Jwks.of({ resolve }),
    issuerOf: (key: Jwk.PublicKey): SigningKeyAuthority | undefined => authorities.get(key),
  };
});

/** Microsoft Entra ID issuer and per-key `issuer` verification policy. */
export const makeEntraIssuerPolicy = (options: {
  readonly signingKeyIssuerRequired: boolean;
  readonly expectedTenantId?: string | undefined;
  readonly excludedTenantId?: string | undefined;
  readonly caseInsensitiveTenantId?: boolean | undefined;
  readonly issuerOf: (key: Jwk.PublicKey) => SigningKeyAuthority | undefined;
}): Oidc.IssuerPolicy =>
  Effect.fnUntraced(function* ({ configuredIssuer, tokenIssuer, claims, signingKey }) {
    const tenantTemplate = isTenantIssuerTemplate(configuredIssuer);
    const caseInsensitiveTenantId = options.caseInsensitiveTenantId === true;

    const expectedTenantId = caseInsensitiveTenantId
      ? options.expectedTenantId?.toLowerCase()
      : options.expectedTenantId;

    const excludedTenantId = options.excludedTenantId?.toLowerCase();

    if (tenantTemplate) {
      const tenant = yield* Schema.decodeUnknownEffect(TenantClaim)(claims).pipe(
        Effect.mapError(issuerFailed),
      );

      if (excludedTenantId !== undefined && tenant.tid.toLowerCase() === excludedTenantId) {
        return yield* issuerFailed();
      }

      const expected = substituteTenantIssuer(configuredIssuer, tenant.tid);

      if (expected === undefined || tokenIssuer !== expected) return yield* issuerFailed();
    } else if (tokenIssuer !== configuredIssuer) {
      return yield* issuerFailed();
    }

    if (expectedTenantId !== undefined) {
      const tenant = yield* Schema.decodeUnknownEffect(TenantClaim)(claims).pipe(
        Effect.mapError(issuerFailed),
      );

      const actualTenantId = caseInsensitiveTenantId ? tenant.tid.toLowerCase() : tenant.tid;

      if (actualTenantId !== expectedTenantId) {
        return yield* issuerFailed();
      }
    }

    const authority = signingKey === undefined ? undefined : options.issuerOf(signingKey);

    if (signingKey !== undefined && authority === undefined) {
      return yield* issuerFailed();
    }

    const keyIssuer = authority?.issuer;

    if (tenantTemplate || options.signingKeyIssuerRequired || keyIssuer !== undefined) {
      if (signingKey === undefined || keyIssuer === undefined) return yield* issuerFailed();

      const allowed = isTenantIssuerTemplate(keyIssuer)
        ? substituteTenantIssuer(
            keyIssuer,
            (yield* Schema.decodeUnknownEffect(TenantClaim)(claims).pipe(
              Effect.mapError(issuerFailed),
            )).tid,
          )
        : keyIssuer;

      if (allowed !== tokenIssuer) return yield* issuerFailed();
    }
  });
