import * as OAuthProtocolClient from "@yielded/oauth/OAuth";
import * as Cause from "effect/Cause";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Cookies from "effect/http/Cookies";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as SchemaAST from "effect/SchemaAST";
import * as Scope from "effect/Scope";

import { AuthRequest } from "../auth/AuthRequest";
import { HookDenied } from "../hooks/models";
import { reportAuthFailure, ReportedOperationDefect } from "../internal/diagnostics";
import { OAuthCallbackTransport } from "../oauth/signInModels";
import type { AuthInvocation } from "../operations/context";
import {
  AuthCredentialCommandCollector,
  AuthRevealCommandCollectorService,
  type AuthCredentialCommand,
} from "../operations/credentials";
import type { AuthRevealCommand } from "../operations/reveals";
import { sessionCacheTransport } from "../sessions/cookieCache";
import {
  cacheSessionInvocation,
  CurrentSessionInvocation,
  SessionVerificationCapture,
  withSessionInvocation,
  withSessionRequest,
} from "../sessions/invocation";
import {
  type AnyRoute,
  HttpRequestBody,
  type RouteRequirements,
  type RouteSuccess,
  type RouteFailure,
} from "./contract";
import { OperationHttpConfigurationError, OperationHttpError } from "./errors";
import type { HttpCredentials, OperationHttpConfiguration } from "./models";
import { OperationHttpInvocation } from "./OperationHttpInvocation";
import { OperationHttpServerConfig } from "./OperationHttpServerConfig";
import { RevealWire, nativeCredentialHeader, revealWire } from "./private";
import { requestSecurity } from "./security";
import { rotationCookies, snapshotCookie } from "./session-cache-cookie";

const responseSchema = Schema.Union([
  Schema.TaggedStruct("Success", {
    value: Schema.optionalKey(Schema.Json),
    private: Schema.optionalKey(Schema.Array(RevealWire)),
  }),
  Schema.TaggedStruct("Failure", { error: Schema.Json }),
  Schema.TaggedStruct("TransportFailure", { reason: Schema.String }),
]);

const encodeResponse = Schema.encodeEffect(Schema.fromJsonString(responseSchema));
const decodeRequestBody = Schema.decodeEffect(Schema.fromJsonString(HttpRequestBody));

export interface OAuthHttpCallback<R = never> {
  readonly route: AnyRoute;
  readonly path: string;
  readonly provider: string;
  readonly callbackId: string;
  /** Resolve the original public flow ID from application-owned callback custody.
   * The operation independently authenticates its state and private request binder. */
  readonly flowId: (
    request: Request,
    credentials: HttpCredentials,
  ) => Effect.Effect<string, OperationHttpError>;
  readonly allowedRedirectOrigins: ReadonlyArray<string>;
  readonly allowedQueryParameters?: ReadonlyArray<string>;
  /** Named Auth actions read the private binder from AuthRequest themselves. */
  readonly requestBinding?: "context";
  /** Override the default returnTarget redirect using the schema-encoded result.
   * Credential delivery and non-cacheable response headers remain host-owned. */
  readonly respond?: (
    value: Schema.Json | undefined,
    input: { readonly flowId: string; readonly provider: string; readonly callbackId: string },
  ) => Effect.Effect<Response, OperationHttpError, R>;
}

const maxCompiledCallbackAllowlist = 255;

const forbiddenCallbackAllowlistNames: ReadonlySet<string> = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "access_token",
  "id_token",
  "token",
  "token_type",
  "expires_in",
  "response",
]);

const isWellFormedUnicode = (value: string): boolean => {
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

export const compileCallbackAllowlist = (
  names: ReadonlyArray<string> | undefined,
): ReadonlyArray<string> | undefined => {
  if (names === undefined) return undefined;
  const unique = new Set<string>();

  for (const name of names) {
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      name.length > 256 ||
      !isWellFormedUnicode(name) ||
      // oxlint-disable-next-line no-control-regex -- Reject ASCII control characters in callback parameter allowlists.
      /[\u0000-\u001f\u007f]/u.test(name) ||
      forbiddenCallbackAllowlistNames.has(name.toLowerCase()) ||
      forbiddenCallbackAllowlistNames.has(name)
    )
      // oxlint-disable-next-line effect/no-untyped-throw -- Public synchronous callback construction rejects an invalid parameter allowlist before mounting.
      throw OperationHttpConfigurationError.make({ reason: "callback" });
    unique.add(name);
    if (unique.size > maxCompiledCallbackAllowlist)
      // oxlint-disable-next-line effect/no-untyped-throw -- Public synchronous callback construction rejects an oversized parameter allowlist before mounting.
      throw OperationHttpConfigurationError.make({ reason: "callback" });
  }

  return Object.freeze([...unique]);
};

export const oauthCallback = <R extends AnyRoute, ResponseR = never>(
  route: R,
  options: Omit<OAuthHttpCallback<ResponseR>, "route">,
): OAuthHttpCallback<ResponseR> & { readonly route: R } => {
  if (
    !options.path.startsWith("/") ||
    options.path.includes("?") ||
    (options.requestBinding !== "context" &&
      !Object.values(route.credentials).includes("request-binding")) ||
    route.operation.replay !== "single-use"
  )
    // oxlint-disable-next-line effect/no-untyped-throw -- Public synchronous callback construction rejects an invalid route before mounting.
    throw OperationHttpConfigurationError.make({ reason: "callback" });

  const allowedQueryParameters = compileCallbackAllowlist(options.allowedQueryParameters);

  return Object.freeze({
    ...options,
    route,
    allowedRedirectOrigins: Object.freeze([...options.allowedRedirectOrigins]),
    ...(allowedQueryParameters === undefined ? {} : { allowedQueryParameters }),
  });
};

const boundedBytes = Effect.fnUntraced(function* (request: Request, maximum: number) {
  if (request.body === null) return new Uint8Array(0);
  const body = request.body;
  let readFailed = false;

  const result = yield* Effect.acquireUseRelease(
    Effect.sync(() => body.getReader()),
    (reader) =>
      Effect.tryPromise({
        try: async () => {
          const chunks: Uint8Array[] = [];
          let bytes = 0;

          while (true) {
            const next = await reader.read();

            if (next.done) break;
            bytes += next.value.byteLength;
            if (bytes > maximum) return { _tag: "TooLarge" as const };
            chunks.push(next.value);
          }
          const output = new Uint8Array(bytes);
          let offset = 0;

          for (const chunk of chunks) {
            output.set(chunk, offset);
            offset += chunk.byteLength;
          }

          return { _tag: "Bytes" as const, bytes: output };
        },
        catch: () => {
          readFailed = true;

          return OperationHttpError.make({ reason: "request" });
        },
      }),
    (reader) =>
      Effect.promise(async () => {
        try {
          // Errored streams reject cancel with the already-handled read failure.
          if (!readFailed) await reader.cancel();
        } finally {
          reader.releaseLock();
        }
      }),
  );

  if (result._tag === "TooLarge") return yield* OperationHttpError.make({ reason: "too-large" });

  return result.bytes;
});

const boundedText = Effect.fnUntraced(function* (request: Request, maximum: number) {
  const bytes = yield* boundedBytes(request, maximum);

  return yield* Effect.try({
    try: () => new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    catch: () => OperationHttpError.make({ reason: "request" }),
  });
});

const baseHeaders = () =>
  new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    pragma: "no-cache",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    vary: "Origin",
  });

const failResponse = (error: OperationHttpError) =>
  Effect.map(
    encodeResponse({ _tag: "TransportFailure", reason: error.reason }),
    (body) =>
      new Response(body, {
        status:
          error.reason === "not-found"
            ? 404
            : error.reason === "method"
              ? 405
              : error.reason === "too-large"
                ? 413
                : error.reason === "unavailable"
                  ? 503
                  : error.reason === "origin" || error.reason === "csrf"
                    ? 403
                    : 400,
        headers: baseHeaders(),
      }),
  ).pipe(Effect.orDie);

const callbackPayload = Effect.fn("OperationHttp.callbackPayload")(function* (
  callback: OAuthHttpCallback<unknown>,
  request: Request,
  credentials: HttpCredentials,
  url: URL,
) {
  const configuredAllowlist = callback.allowedQueryParameters;

  let decoded: OAuthProtocolClient.CallbackParams;

  if (request.method === "GET") {
    decoded = yield* OAuthProtocolClient.callbackParamsFromQuery(url, {
      ...(configuredAllowlist === undefined ? {} : { allowedParameters: configuredAllowlist }),
      unknownParameters: "reject",
    }).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "request" })));
  } else if (request.method === "POST") {
    const contentType = request.headers.get("content-type");

    if (
      url.search !== "" ||
      contentType?.split(";")[0]?.trim().toLowerCase() !== "application/x-www-form-urlencoded"
    ) {
      return yield* OperationHttpError.make({ reason: "request" });
    }
    const config = yield* OperationHttpServerConfig;
    const maxBytes = Math.min(config.maximumBodyBytes, 16384);

    const body = yield* boundedBytes(request, maxBytes).pipe(
      Effect.mapError((error) =>
        error.reason === "too-large" && 16384 < config.maximumBodyBytes
          ? OperationHttpError.make({ reason: "request" })
          : error,
      ),
    );

    const postAllowlist =
      configuredAllowlist === undefined
        ? ["user"]
        : configuredAllowlist.includes("user")
          ? configuredAllowlist
          : [...configuredAllowlist, "user"];

    decoded = yield* OAuthProtocolClient.callbackParamsFromFormPost({
      url,
      contentType: contentType ?? undefined,
      body,
      maxBytes,
      allowedParameters: postAllowlist,
      unknownParameters: "reject",
    }).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "request" })));
  } else {
    return yield* OperationHttpError.make({ reason: "method" });
  }

  const state = Redacted.value(decoded.state);

  if (state.length > 2048) return yield* OperationHttpError.make({ reason: "request" });

  let response:
    | {
        readonly _tag: "Error";
        readonly state: string;
        readonly error: "access-denied" | "rejected";
        readonly issuer?: string;
      }
    | {
        readonly _tag: "Code";
        readonly state: string;
        readonly code: string;
        readonly issuer?: string;
        readonly scope?: string;
        readonly user?: string;
      };

  if (decoded.outcome._tag === "Error") {
    response = {
      _tag: "Error",
      state,
      error: decoded.outcome.code === "access_denied" ? "access-denied" : "rejected",
      ...(decoded.issuer === undefined ? {} : { issuer: decoded.issuer }),
    };
  } else {
    const user =
      decoded.mode === "form_post" && Object.hasOwn(decoded.outcome.extra, "user")
        ? decoded.outcome.extra.user
        : undefined;

    response = {
      _tag: "Code",
      state,
      code: Redacted.value(decoded.outcome.code),
      ...(decoded.issuer === undefined ? {} : { issuer: decoded.issuer }),
      ...(decoded.outcome.scope === undefined ? {} : { scope: decoded.outcome.scope }),
      ...(user === undefined || user.length === 0 ? {} : { user }),
    };
  }

  return {
    mode: decoded.mode,
    payload: {
      flowId: yield* callback.flowId(request, credentials),
      provider: callback.provider,
      callbackId: callback.callbackId,
      response,
    },
  };
});

const inject = (route: AnyRoute, input: unknown, credentials: HttpCredentials) =>
  Effect.suspend(() =>
    Effect.fromResult(
      Result.try({
        try: () =>
          Result.gen(function* () {
            const fields = Object.entries(route.credentials);

            if (fields.length === 0) return input;

            const output = {
              // oxlint-disable-next-line no-restricted-properties -- Capture the untyped HTTP payload and private fields together before yielding.
              ...(yield* Schema.decodeUnknownResult(Schema.Record(Schema.String, Schema.Unknown))(
                input,
              )),
            };

            for (const [field, slot] of fields) {
              if (Object.hasOwn(output, field))
                return yield* Result.fail(OperationHttpError.make({ reason: "credentials" }));
              const credential = credentials[slot];

              if (credential === undefined)
                return yield* Result.fail(OperationHttpError.make({ reason: "credentials" }));
              output[field] = Redacted.value(credential);
            }

            return output;
          }),
        catch: () => OperationHttpError.make({ reason: "credentials" }),
      }).pipe(
        Result.flatMap((result) => result),
        Result.mapError(() => OperationHttpError.make({ reason: "credentials" })),
      ),
    ),
  );

const applyCommands = Effect.fnUntraced(function* (
  headers: Headers,
  commands: ReadonlyArray<AuthCredentialCommand>,
  config: OperationHttpConfiguration,
  native: boolean,
  cacheEnabled: boolean,
) {
  const now = DateTime.toEpochMillis(yield* DateTime.now);

  for (const command of commands) {
    if (command.slot === "session-cache") {
      if (native || !cacheEnabled) continue;
      const cookie = yield* snapshotCookie(config.cookies["session-cache"], command, now);

      if (cookie !== undefined) headers.append("set-cookie", Cookies.serializeCookie(cookie));
      continue;
    }
    if (native) {
      headers.set(config.native!.responseHeaders[command.slot], nativeCredentialHeader(command));
    } else {
      const cookie = config.cookies[command.slot];
      const value = command._tag === "Issue" ? Redacted.value(command.credential) : "";
      const maxAge = command._tag === "Issue" ? Math.max(0, command.expiresAtMillis - now) : 0;

      const sameSite =
        command._tag === "Issue" && command.sameSite === "none" ? "none" : cookie.sameSite;

      if (sameSite === "none" && !cookie.secure)
        return yield* OperationHttpError.make({ reason: "credentials" });

      headers.append(
        "set-cookie",
        Cookies.serializeCookie(
          Cookies.makeCookieUnsafe(cookie.name, value, {
            path: cookie.path,
            secure: cookie.secure,
            sameSite,
            httpOnly: true,
            ...(cookie.domain === undefined ? {} : { domain: cookie.domain }),
            maxAge: Duration.millis(maxAge),
          }),
        ),
      );
    }
  }
});

/** Retain transport configuration and caller resolution only. Supply operation,
 * codec and callback services to each handle invocation instead of construction. */
export const make = Effect.fnUntraced(function* <
  const Routes extends Readonly<Record<string, AnyRoute>>,
  const Callbacks extends ReadonlyArray<OAuthHttpCallback<unknown>> = readonly [],
>(contract: { readonly routes: Routes }, options?: { readonly callbacks?: Callbacks }) {
  type DispatchRoute = Routes[keyof Routes] | Callbacks[number]["route"];
  type Requirements = Exclude<
    | RouteRequirements<DispatchRoute>
    | Effect.Services<ReturnType<NonNullable<Callbacks[number]["respond"]>>>,
    AuthRequest | AuthCredentialCommandCollector | AuthRevealCommandCollectorService | Scope.Scope
  >;
  const config = yield* OperationHttpServerConfig;
  const invocation = yield* OperationHttpInvocation;
  const cacheTransport = invocation[sessionCacheTransport];

  for (const route of Object.values(contract.routes)) {
    if (
      route.method === "GET" &&
      (route.operation.replay !== "read-only" ||
        route.operation.credentials ||
        route.reveals.length > 0 ||
        route.operation.reveals.length > 0 ||
        Object.keys(route.credentials).length > 0 ||
        !(
          SchemaAST.isVoid(Schema.toEncoded(route.operation.rpc.payloadSchema).ast) ||
          SchemaAST.isUndefined(Schema.toEncoded(route.operation.rpc.payloadSchema).ast)
        ))
    )
      return yield* OperationHttpConfigurationError.make({ reason: "route" });
  }
  const routes = new Map(Object.values(contract.routes).map((route) => [route.path, route]));
  const callbacks = new Map<string, Callbacks[number]>();

  for (const callback of options?.callbacks ?? []) {
    if (callbacks.has(callback.path) || routes.has(callback.path))
      return yield* OperationHttpConfigurationError.make({ reason: "duplicate-route" });
    callbacks.set(callback.path, callback);
  }

  const handleRequest = Effect.fn("OperationHttp.handle")(
    function* (request: Request, mutationCookies: Cookies.Cookie[]) {
      const services = (yield* Effect.context<Requirements>()).pipe(
        Context.omit(CurrentSessionInvocation, SessionVerificationCapture),
      );

      if (new TextEncoder().encode(request.url).byteLength > config.maximumUrlBytes)
        return yield* OperationHttpError.make({ reason: "too-large" });

      const url = yield* Effect.try({
        try: () => new URL(request.url),
        catch: () => OperationHttpError.make({ reason: "request" }),
      });

      const callback = callbacks.get(url.pathname);
      const route = callback?.route ?? routes.get(url.pathname);

      if (route === undefined) return yield* OperationHttpError.make({ reason: "not-found" });
      if (request.method === "OPTIONS" && callback === undefined) {
        const origin = request.headers.get("origin");

        const requestedHeaders = (request.headers.get("access-control-request-headers") ?? "")
          .toLowerCase()
          .split(",")
          .map((header) => header.trim())
          .filter(Boolean);

        if (origin === null || !config.trustedOrigins.includes(origin))
          return yield* OperationHttpError.make({ reason: "origin" });
        if (
          url.search !== "" ||
          request.headers.get("access-control-request-method") !== route.method ||
          requestedHeaders.some(
            (header) => header !== "content-type" && header !== config.csrfHeader,
          )
        )
          return yield* OperationHttpError.make({ reason: "csrf" });
        const headers = baseHeaders();

        headers.set("access-control-allow-origin", origin);
        headers.set("access-control-allow-credentials", "true");
        headers.set("access-control-allow-methods", route.method);
        headers.set("access-control-allow-headers", `content-type, ${config.csrfHeader}`);
        headers.set(
          "vary",
          "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        );

        return new Response(null, { status: 204, headers });
      }
      if (
        request.method !==
        (callback === undefined ? route.method : request.method === "POST" ? "POST" : "GET")
      )
        return yield* OperationHttpError.make({ reason: "method" });
      if (callback === undefined && url.search !== "")
        return yield* OperationHttpError.make({ reason: "request" });

      const security = yield* requestSecurity(
        request,
        callback === undefined ? (route.method === "GET" ? "read" : "operation") : "callback",
      );

      if (callback !== undefined && security.credentials["request-binding"] === undefined)
        return yield* OperationHttpError.make({ reason: "credentials" });

      let callbackMode: "query" | "form_post" = "query";
      let raw: unknown;

      if (callback === undefined && route.method === "GET") {
        raw = undefined;
      } else if (callback === undefined) {
        raw = (yield* decodeRequestBody(yield* boundedText(request, config.maximumBodyBytes)).pipe(
          Effect.mapError(() => OperationHttpError.make({ reason: "request" })),
        )).payload;
      } else {
        const decodedCallback = yield* callbackPayload(
          callback,
          request,
          security.credentials,
          url,
        );

        raw = decodedCallback.payload;
        callbackMode = decodedCallback.mode;
      }

      const payload = yield* inject(route, raw, security.credentials);

      // POST admission (or callback binding) already ran above. Share one
      // rotation with nested auth mutations, including payload-bearing queries.
      const rotateCache =
        security.native || cacheTransport === undefined
          ? Effect.void
          : yield* Effect.cached(
              Effect.gen(function* () {
                const generation = yield* cacheTransport.rotate;

                mutationCookies.push(
                  ...(yield* rotationCookies(
                    config.cookies["session-cache"],
                    generation,
                    cacheTransport.lifetimeMillis,
                  )),
                );
              }),
            );

      const invalidateCache = rotateCache.pipe(
        Effect.mapError(() => OperationHttpError.make({ reason: "unavailable" })),
      );

      if (route.operation.replay !== "read-only") yield* invalidateCache;
      const trusted = yield* invocation.resolve(request, security.credentials);

      const commands: AuthCredentialCommand[] = [];

      const reveals: AuthRevealCommand[] = [];

      const sink = (values: ReadonlyArray<AuthCredentialCommand>) =>
        Effect.sync(() => {
          commands.push(...values);
        });

      const collector = {
        supportedKinds: route.reveals,
        accept: (values: ReadonlyArray<AuthRevealCommand>) =>
          Effect.sync(() => {
            reveals.push(...values);
          }),
      };

      // The selected table entry couples its handler and codecs. The maker's
      // generic requirements retain every concrete entry before this dispatch.
      const invoke = route.operation.invokeUnknown as (
        invocation: AuthInvocation,
        input: unknown,
      ) => Effect.Effect<RouteSuccess<DispatchRoute>, RouteFailure<DispatchRoute>, Requirements>;

      const call = invoke(trusted, payload);

      const successSchema = route.operation.rpc.successSchema as Schema.Codec<
        RouteSuccess<DispatchRoute>,
        unknown,
        unknown,
        Requirements
      >;

      const errorSchema = route.operation.rpc.errorSchema as Schema.Codec<
        RouteFailure<DispatchRoute>,
        unknown,
        unknown,
        Requirements
      >;

      // Context captures retain all runtime entries, regardless of their static
      // requirement type. Replace request-owned services before every invocation
      // and wire projection so ambient collectors can never receive secrets.
      const requestScope = yield* Effect.scope;

      const resolveInvocation =
        invocation.request === undefined
          ? undefined
          : yield* cacheSessionInvocation(invocation.request(request, security.credentials));

      const requestServices = services.pipe(
        Context.add(Scope.Scope, requestScope),
        Context.add(OAuthCallbackTransport, { mode: callbackMode }),
        Context.add(AuthRequest, {
          invocation: trusted,
          ...(resolveInvocation === undefined ? {} : { resolveInvocation }),
          credentials: security.credentials,
          actionMode: route.operation.replay === "read-only" ? "query" : "mutation",
          ...(security.sessionCacheGeneration === undefined
            ? {}
            : { sessionCacheGeneration: security.sessionCacheGeneration }),
          ...(security.native || cacheTransport === undefined
            ? {}
            : {
                initializeSessionCache: rotateCache,
                sessionCacheCommandSink: (command) =>
                  Effect.sync(() => {
                    commands.push(command);
                  }),
              }),
          beforeMutation:
            route.method === "GET"
              ? HookDenied.make({ reason: "policy" })
              : invalidateCache.pipe(
                  Effect.mapError(() => HookDenied.make({ reason: "unavailable" })),
                ),
          credentialCommandSink: sink,
          revealCommandCollector: collector,
        }),
        Context.add(AuthCredentialCommandCollector, sink),
        Context.add(AuthRevealCommandCollectorService, collector),
      );

      const resolved = yield* Effect.exit(
        withSessionInvocation(Effect.succeed(trusted), () =>
          call.pipe(Effect.provide(requestServices)),
        ),
      );

      const headers = baseHeaders();

      if (
        security.requestOrigin !== null &&
        config.trustedOrigins.includes(security.requestOrigin)
      ) {
        headers.set("access-control-allow-origin", security.requestOrigin);
        headers.set("access-control-allow-credentials", "true");
      }
      if (resolved._tag === "Failure") {
        // A typed response cannot represent a concurrent defect or cancellation.
        if (Cause.hasDies(resolved.cause) || Cause.hasInterrupts(resolved.cause))
          return yield* Effect.failCause(resolved.cause);
        const failure = resolved.cause.reasons.find(Cause.isFailReason);

        if (failure === undefined) return yield* Effect.failCause(resolved.cause);
        yield* applyCommands(
          headers,
          commands.filter(
            (command) => command.slot === "session-cache" && command._tag === "Clear",
          ),
          config,
          security.native,
          cacheTransport !== undefined,
        );

        const encoded = yield* Schema.encodeEffect(errorSchema)(failure.error).pipe(
          Effect.provide(requestServices),
          Effect.mapError(() => OperationHttpError.make({ reason: "response" })),
        );

        // oxlint-disable-next-line no-restricted-properties -- an encoded operation error enters the JSON transport boundary.
        const error = yield* Schema.decodeUnknownEffect(Schema.Json)(encoded).pipe(
          Effect.mapError(() => OperationHttpError.make({ reason: "response" })),
        );

        return new Response(yield* encodeResponse({ _tag: "Failure", error }).pipe(Effect.orDie), {
          status: 400,
          headers,
        });
      }

      const encoded = yield* Schema.encodeEffect(successSchema)(resolved.value).pipe(
        Effect.provide(requestServices),
        Effect.mapError(() => OperationHttpError.make({ reason: "response" })),
      );

      const value =
        encoded === undefined
          ? undefined
          : // oxlint-disable-next-line no-restricted-properties -- schema-encoded success enters the JSON boundary.
            yield* Schema.decodeUnknownEffect(Schema.Json)(encoded).pipe(
              Effect.mapError(() => OperationHttpError.make({ reason: "response" })),
            );

      if (callback?.respond === undefined)
        yield* applyCommands(
          headers,
          commands,
          config,
          security.native,
          cacheTransport !== undefined,
        );
      if (callback !== undefined) {
        if (callback.respond !== undefined) {
          // The callback retains its exact invocation requirements.
          const respond = callback.respond as NonNullable<
            OAuthHttpCallback<Requirements>["respond"]
          >;

          const input = yield* Schema.decodeUnknownEffect(Schema.Struct({ flowId: Schema.String }))(
            raw,
          ).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "response" })));

          const response = yield* respond(value, {
            ...input,
            provider: callback.provider,
            callbackId: callback.callbackId,
          }).pipe(Effect.provide(requestServices));

          yield* applyCommands(
            headers,
            commands,
            config,
            security.native,
            cacheTransport !== undefined,
          );

          const customHeaders = new Headers(response.headers);

          for (const name of [
            "cache-control",
            "pragma",
            "referrer-policy",
            "x-content-type-options",
          ])
            customHeaders.set(name, headers.get(name)!);
          for (const cookie of headers.getSetCookie()) customHeaders.append("set-cookie", cookie);

          return new Response(response.body, { status: response.status, headers: customHeaders });
        }

        // oxlint-disable-next-line no-restricted-properties -- only the core-approved return target is projected from the callback result.
        const target = yield* Schema.decodeUnknownEffect(
          Schema.Struct({ returnTarget: Schema.String.check(Schema.isMaxLength(2048)) }),
        )(encoded).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "response" })));

        const destination = yield* Effect.try({
          try: () => new URL(target.returnTarget, security.publicOrigin),
          catch: () => OperationHttpError.make({ reason: "response" }),
        });

        if (
          (destination.origin !== security.publicOrigin &&
            !callback.allowedRedirectOrigins.includes(destination.origin)) ||
          !["https:", "http:"].includes(destination.protocol) ||
          destination.username !== "" ||
          destination.password !== ""
        )
          return yield* OperationHttpError.make({ reason: "response" });
        headers.set("location", destination.href);

        return new Response(null, { status: 303, headers });
      }

      return new Response(
        yield* encodeResponse({
          _tag: "Success",
          ...(value === undefined ? {} : { value }),
          ...(reveals.length === 0 ? {} : { private: reveals.map(revealWire) }),
        }).pipe(Effect.orDie),
        { status: 200, headers },
      );
    },
    Effect.scoped,
    Effect.provideService(OperationHttpServerConfig, config),
  );

  const handle = Effect.fnUntraced(function* (request: Request) {
    // Mutation binding survives typed errors, defects and response projection
    // failures. Only these invalidation cookies may cross a failed boundary.
    const mutationCookies: Cookies.Cookie[] = [];

    return yield* handleRequest(request, mutationCookies).pipe(
      withSessionRequest,
      Effect.catchCause((cause) => {
        if (Cause.hasDies(cause))
          return reportAuthFailure("http", cause).pipe(
            Effect.andThen(
              Cause.hasInterrupts(cause)
                ? Effect.failCause(
                    Cause.fromReasons<never>([
                      Cause.makeDieReason(ReportedOperationDefect.make({})),
                      ...cause.reasons.filter(Cause.isInterruptReason),
                    ]),
                  )
                : failResponse(OperationHttpError.make({ reason: "unavailable" })),
            ),
          );
        if (Cause.hasInterrupts(cause))
          return Effect.failCause(
            Cause.fromReasons<never>(cause.reasons.filter(Cause.isInterruptReason)),
          );
        const failure = cause.reasons.find(Cause.isFailReason);

        return failResponse(
          failure !== undefined && Schema.is(OperationHttpError)(failure.error)
            ? failure.error
            : OperationHttpError.make({ reason: "unavailable" }),
        );
      }),
      Effect.map((response) => {
        if (mutationCookies.length === 0) return response;
        const headers = new Headers(response.headers);

        for (const cookie of mutationCookies)
          headers.append("set-cookie", Cookies.serializeCookie(cookie));

        return new Response(response.body, { status: response.status, headers });
      }),
    );
  });

  return { handle };
});
