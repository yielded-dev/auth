import { DateTime, Effect, Redacted, Schema, Semaphore } from "effect";

import type { AuthCredentialCommand, CredentialSlot } from "../operations/credentials";
import { snapshotRevealCommands, type AuthRevealCommandCollector } from "../operations/reveals";
import { headerName } from "./configuration-schema";
import {
  type AnyRoute,
  HttpRequestBody,
  type RouteFailure,
  type RouteInput,
  type RouteSuccess,
} from "./contract";
import { OperationHttpError } from "./errors";
import type { HttpCredentials } from "./models";
import { CredentialWire, RevealWire, credentialSlots, decodeRevealWire } from "./private";

export interface OperationFetchOptions {
  readonly baseUrl: string;
  readonly csrfHeader: string;
  readonly csrfValue: string;
  readonly maximumResponseBytes?: number;
  readonly fetch?: typeof globalThis.fetch;
  readonly privateOutput?: AuthRevealCommandCollector & { readonly clear: Effect.Effect<void> };
  readonly native?: {
    readonly modeHeader: string;
    readonly requestHeaders: Readonly<Record<CredentialSlot, string>>;
    readonly responseHeaders: Readonly<Record<CredentialSlot, string>>;
    readonly read: Effect.Effect<HttpCredentials, OperationHttpError>;
    readonly accept: (
      commands: ReadonlyArray<AuthCredentialCommand>,
    ) => Effect.Effect<void, OperationHttpError>;
  };
}

export interface OperationCallOptions<Success = unknown> {
  readonly replaceSubject?: boolean | ((success: Success) => boolean);
  /** Runs inside credential admission after fencing old responses. The callback
   * must not call this client's transition or start another credential call. */
  readonly onTransition?: Effect.Effect<void>;
}

export interface OperationFetchClient {
  readonly call: <R extends AnyRoute>(
    route: R,
    input: RouteInput<R>,
    options?: OperationCallOptions<RouteSuccess<R>>,
  ) => Effect.Effect<
    RouteSuccess<R>,
    RouteFailure<R> | OperationHttpError,
    | R["operation"]["rpc"]["successSchema"]["DecodingServices"]
    | R["operation"]["rpc"]["errorSchema"]["DecodingServices"]
  >;
  /** Wait for admitted credential responses, then fence old queries and clear reveals.
   * All authenticated subject changes for this client must pass this boundary. */
  readonly transition: Effect.Effect<void>;
  readonly generation: Effect.Effect<number>;
}

/** Complete an authentication operation and publish its subject while its
 * credential response remains admitted. Undefined preserves a pending flow. */
export interface OperationAuthenticationCompletion {
  <R extends AnyRoute>(
    route: R,
    input: RouteInput<R>,
    fromSuccess: (success: RouteSuccess<R>) => string | null | undefined,
    options?: { readonly onTransition?: Effect.Effect<void> },
  ): Effect.Effect<
    RouteSuccess<R>,
    RouteFailure<R> | OperationHttpError,
    | R["operation"]["rpc"]["successSchema"]["DecodingServices"]
    | R["operation"]["rpc"]["errorSchema"]["DecodingServices"]
  >;
}

/** The caller owns the lifecycle gate and publisher. Publishers must not call
 * the transport: they run under credential admission, before reveal acceptance. */
export const makeAuthenticationCompletion = (
  client: OperationFetchClient,
  gate: Semaphore.Semaphore,
  publishSubject: (subject: string | null) => Effect.Effect<void>,
): OperationAuthenticationCompletion =>
  Effect.fn("OperationHttpClient.completeAuthentication")(function* <R extends AnyRoute>(
    route: R,
    input: RouteInput<R>,
    fromSuccess: (success: RouteSuccess<R>) => string | null | undefined,
    options?: { readonly onTransition?: Effect.Effect<void> },
  ) {
    const started = yield* client.generation;

    return yield* gate.withPermits(1)(
      Effect.gen(function* () {
        if ((yield* client.generation) !== started)
          return yield* OperationHttpError.make({ reason: "stale-response" });

        return yield* Effect.uninterruptible(
          Effect.gen(function* () {
            let nextSubject: string | null | undefined;

            return yield* client.call(route, input, {
              replaceSubject: (value) => {
                nextSubject = fromSuccess(value);

                return nextSubject !== undefined;
              },
              onTransition: Effect.suspend(() =>
                nextSubject === undefined
                  ? Effect.void
                  : publishSubject(nextSubject).pipe(
                      Effect.andThen(options?.onTransition ?? Effect.void),
                    ),
              ),
            });
          }).pipe(
            // A failed response can follow a cookie already accepted by the
            // browser. Remove the old account state without replaying the call.
            Effect.onError(() =>
              Effect.gen(function* () {
                yield* client.transition;
                yield* publishSubject(null);
                yield* options?.onTransition ?? Effect.void;
              }),
            ),
          ),
        );
      }),
    );
  });

const responseCodec = Schema.fromJsonString(
  Schema.Union([
    Schema.TaggedStruct("Success", {
      value: Schema.optionalKey(Schema.Json),
      private: Schema.optionalKey(Schema.Array(RevealWire)),
    }),
    Schema.TaggedStruct("Failure", { error: Schema.Json }),
    Schema.TaggedStruct("TransportFailure", { reason: Schema.String }),
  ]),
);

const credentialCodec = Schema.fromJsonString(CredentialWire);
const requestCodec = Schema.fromJsonString(HttpRequestBody);

const readBody = (response: Response, maximum: number) =>
  Effect.tryPromise({
    try: async (signal) => {
      if (response.body === null) return "";
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;

      const abort = () => {
        void reader.cancel();
      };

      signal.addEventListener("abort", abort, { once: true });
      try {
        while (true) {
          const part = await reader.read();

          if (part.done) break;
          size += part.value.length;
          if (size > maximum) {
            await reader.cancel();
            throw new Error();
          }
          chunks.push(part.value);
        }
        const bytes = new Uint8Array(size);
        let offset = 0;

        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.length;
        }

        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } finally {
        signal.removeEventListener("abort", abort);
        reader.releaseLock();
      }
    },
    catch: () => OperationHttpError.make({ reason: "response" }),
  });

/** One instance owns credential ordering and stale-result fencing. Share it within
 * a browser authentication lifetime; mutations are never automatically retried. */
export const make = Effect.fn("OperationHttpClient.make")(function* (
  options: OperationFetchOptions,
): Effect.fn.Return<OperationFetchClient, OperationHttpError> {
  const base = yield* Effect.try({
    try: () => new URL(options.baseUrl),
    catch: () => OperationHttpError.make({ reason: "request" }),
  });

  if (
    !Number.isSafeInteger(options.maximumResponseBytes ?? 1048576) ||
    (options.maximumResponseBytes ?? 1048576) < 1 ||
    (options.maximumResponseBytes ?? 1048576) > 1048576 ||
    !/^x-[a-z0-9-]{1,61}$/.test(options.csrfHeader) ||
    options.csrfValue.length < 1 ||
    options.csrfValue.length > 128 ||
    !["https:", "http:"].includes(base.protocol) ||
    base.username !== "" ||
    base.password !== "" ||
    base.search !== "" ||
    base.hash !== ""
  )
    return yield* OperationHttpError.make({ reason: "request" });
  if (options.native !== undefined) {
    const names = [
      options.native.modeHeader,
      ...credentialSlots.map((slot) => options.native!.requestHeaders[slot]),
    ];

    const response = credentialSlots.map((slot) => options.native!.responseHeaders[slot]);

    if (
      [...names, ...response].some((name) => !Schema.is(headerName)(name)) ||
      new Set(names).size !== names.length ||
      new Set(response).size !== response.length ||
      names.includes(options.csrfHeader)
    )
      return yield* OperationHttpError.make({ reason: "request" });
  }
  const gate = yield* Semaphore.make(1);
  let generation = 0;

  const advance = Effect.gen(function* () {
    generation++;
    if (options.privateOutput !== undefined) yield* options.privateOutput.clear;
  });

  const call = Effect.fn("OperationHttpClient.call")(function* <R extends AnyRoute>(
    route: R,
    input: RouteInput<R>,
    callOptions?: OperationCallOptions<RouteSuccess<R>>,
  ): Effect.fn.Return<
    RouteSuccess<R>,
    RouteFailure<R> | OperationHttpError,
    | R["operation"]["rpc"]["successSchema"]["DecodingServices"]
    | R["operation"]["rpc"]["errorSchema"]["DecodingServices"]
  > {
    const started = generation;

    const services = yield* Effect.context<
      | R["operation"]["rpc"]["successSchema"]["DecodingServices"]
      | R["operation"]["rpc"]["errorSchema"]["DecodingServices"]
    >();

    type DecoderServices =
      | R["operation"]["rpc"]["successSchema"]["DecodingServices"]
      | R["operation"]["rpc"]["errorSchema"]["DecodingServices"];

    // The route generic retains the exact schemas while heterogeneous property
    // access widens them to Rpc.AnyWithProps. Restore that relationship locally.
    const successSchema = route.operation.rpc.successSchema as Schema.Codec<
      RouteSuccess<R>,
      unknown,
      DecoderServices,
      unknown
    >;

    const errorSchema = route.operation.rpc.errorSchema as Schema.Codec<
      RouteFailure<R>,
      unknown,
      DecoderServices,
      unknown
    >;

    if (
      route.operation.reveals.some(
        (kind) =>
          options.privateOutput === undefined ||
          !options.privateOutput.supportedKinds.includes(kind) ||
          !route.reveals.includes(kind),
      )
    )
      return yield* OperationHttpError.make({ reason: "private-output" });

    const work = Effect.gen(function* () {
      if (started !== generation)
        return yield* OperationHttpError.make({ reason: "stale-response" });

      const payload =
        input === undefined
          ? undefined
          : // oxlint-disable-next-line no-restricted-properties -- untyped input is validated for JSON transport compatibility.
            yield* Schema.decodeUnknownEffect(Schema.Json)(input).pipe(
              Effect.mapError(() => OperationHttpError.make({ reason: "request" })),
            );

      const body = yield* Schema.encodeEffect(requestCodec)(
        payload === undefined ? {} : { payload },
      ).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "request" })));

      if (route.method === "GET" && input !== undefined)
        return yield* OperationHttpError.make({ reason: "request" });

      const headers = new Headers(
        route.method === "GET"
          ? {}
          : {
              "content-type": "application/json",
              [options.csrfHeader]: options.csrfValue,
            },
      );

      if (options.native !== undefined) {
        headers.set(options.native.modeHeader, "native");
        const credentials = yield* options.native.read;

        for (const slot of credentialSlots)
          if (credentials[slot] !== undefined)
            headers.set(options.native.requestHeaders[slot], Redacted.value(credentials[slot]!));
      }
      const destination = new URL(route.path, base);

      const response = yield* Effect.tryPromise({
        try: (signal) => {
          // Native credential reads and schema services may suspend. Admission
          // and fetch dispatch share this synchronous check so an old workflow
          // cannot send a write with a newly installed subject's credentials.
          if (started !== generation) throw OperationHttpError.make({ reason: "stale-response" });

          return (options.fetch ?? globalThis.fetch)(destination, {
            method: route.method,
            headers,
            ...(route.method === "GET" ? {} : { body }),
            credentials: options.native === undefined ? "include" : "omit",
            redirect: "error",
            signal,
          });
        },
        catch: (error) =>
          Schema.is(OperationHttpError)(error)
            ? error
            : OperationHttpError.make({ reason: "network" }),
      });

      if (
        response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !==
        "application/json"
      )
        return yield* OperationHttpError.make({ reason: "response" });

      const envelope = yield* Schema.decodeEffect(responseCodec)(
        yield* readBody(response, options.maximumResponseBytes ?? 1048576),
      ).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "response" })));

      if (started !== generation)
        return yield* OperationHttpError.make({ reason: "stale-response" });
      if (envelope._tag === "TransportFailure")
        return yield* OperationHttpError.make({
          reason:
            envelope.reason === "origin" ||
            envelope.reason === "csrf" ||
            envelope.reason === "credentials" ||
            envelope.reason === "private-output"
              ? envelope.reason
              : "response",
        });
      if (envelope._tag === "Failure") {
        const failure = yield* Schema.decodeEffect(errorSchema)(envelope.error).pipe(
          Effect.provide(services),
          Effect.mapError(() => OperationHttpError.make({ reason: "response" })),
        );

        return yield* Effect.fail(failure as RouteFailure<R>);
      }
      if (!response.ok) return yield* OperationHttpError.make({ reason: "response" });

      const value = yield* Schema.decodeEffect(successSchema)(envelope.value).pipe(
        Effect.provide(services),
        Effect.mapError(() => OperationHttpError.make({ reason: "response" })),
      );

      if (started !== generation)
        return yield* OperationHttpError.make({ reason: "stale-response" });

      const privateCommands = yield* Effect.try({
        try: () =>
          snapshotRevealCommands((envelope.private ?? []).map(decodeRevealWire), route.reveals),
        catch: () => OperationHttpError.make({ reason: "private-output" }),
      });

      const now = DateTime.toEpochMillis(yield* DateTime.now);

      if (
        privateCommands.some(
          (command) => command.expiresAtMillis <= now || command.expiresAtMillis > now + 300_000,
        )
      )
        return yield* OperationHttpError.make({ reason: "private-output" });
      if (privateCommands.length > 0 && options.privateOutput === undefined)
        return yield* OperationHttpError.make({ reason: "private-output" });
      if (options.native !== undefined) {
        const commands: AuthCredentialCommand[] = [];

        for (const slot of credentialSlots) {
          const raw = response.headers.get(options.native.responseHeaders[slot]);

          if (raw === null) continue;
          if (!route.operation.credentials)
            return yield* OperationHttpError.make({ reason: "credentials" });

          const command = yield* Schema.decodeEffect(credentialCodec)(raw).pipe(
            Effect.mapError(() => OperationHttpError.make({ reason: "response" })),
          );

          if (command._tag === "Issue" && command.expiresAtMillis <= now)
            return yield* OperationHttpError.make({ reason: "credentials" });
          commands.push(
            command._tag === "Clear"
              ? { _tag: "Clear", slot }
              : { ...command, slot, credential: Redacted.make(command.credential) },
          );
        }
        if (commands.length > 0) yield* options.native.accept(commands);
      }
      const projectSubject = callOptions?.replaceSubject;

      const replaceSubject =
        typeof projectSubject === "function"
          ? yield* Effect.try({
              try: () => projectSubject(value as RouteSuccess<R>),
              catch: () => OperationHttpError.make({ reason: "response" }),
            })
          : projectSubject === true;

      if (replaceSubject) {
        yield* advance;
        if (callOptions?.onTransition !== undefined) yield* callOptions.onTransition;
      }
      if (privateCommands.length > 0) yield* options.privateOutput!.accept(privateCommands);

      return value as RouteSuccess<R>;
    });

    // Once a credential response is admitted it must settle before the lifetime
    // advances: browsers apply Set-Cookie before JavaScript can inspect a response.
    return yield* route.operation.credentials ||
    route.operation.reveals.length > 0 ||
    (callOptions?.replaceSubject !== undefined && callOptions.replaceSubject !== false)
      ? gate.withPermits(1)(Effect.uninterruptible(work))
      : work;
  });

  return {
    call,
    transition: gate.withPermits(1)(advance),
    generation: Effect.sync(() => generation),
  };
});
