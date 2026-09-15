import { DateTime, Duration, Effect, Layer, Redacted, Schema } from "effect";
import {
  type Binding,
  type Environment,
  DurableObject,
  DurableObjectState,
  Email,
  Worker,
} from "effect-cf";
import type { OtlpExporter } from "effect/unstable/observability";

import { AuthStore, AuthStoreBackend, EmailOtpRejected } from "./AuthStore";
import { EmailOtpSender } from "./EmailOtpSender";
import { AuthRateLimited, AuthStoreError, InvalidRegistration } from "./Errors";
import {
  type TokenDigest as TokenDigestType,
  ConsumeChallenge,
  ConsumeRegistration,
  NewChallenge,
  NewRegistration,
  PendingRegistration,
  TokenDigest,
  VerifiedEmail,
} from "./Schema";

/**
 * Typed RPC contract for the auth store Durable Object. A single named
 * instance backs a deployment: auth traffic is low-rate, and one serialized
 * object makes the store's exactly-once consume guarantees structural.
 * Expected auth failures travel inside the success schemas; the worker-side
 * client re-fails them.
 */
export class AuthStoreObject extends DurableObject.Tag<AuthStoreObject>()(
  "effect-auth/AuthStoreObject",
  {
    issueChallenge: DurableObject.method({
      args: [NewChallenge],
      success: Schema.Union([Schema.Null, AuthRateLimited]),
    }),
    consumeChallenge: DurableObject.method({
      args: [ConsumeChallenge],
      success: Schema.Union([VerifiedEmail, EmailOtpRejected]),
    }),
    issueRegistration: DurableObject.method({
      args: [NewRegistration],
      success: Schema.Null,
    }),
    inspectRegistration: DurableObject.method({
      args: [TokenDigest],
      success: Schema.Union([PendingRegistration, InvalidRegistration]),
    }),
    consumeRegistration: DurableObject.method({
      args: [ConsumeRegistration],
      success: Schema.Union([Schema.Null, InvalidRegistration]),
    }),
  },
) {}

/**
 * The canonical effect-auth store state machine over the object's own
 * storage. The Durable Object's input gates serialize requests; the machine
 * adds its own serialization on top, so exactly-once consumption holds
 * regardless. Export this class from the worker entry module and register it
 * under `durable_objects` in the wrangler configuration.
 */
const BackendLive = Layer.effect(AuthStoreBackend)(
  Effect.map(DurableObjectState.DurableObjectState, (state) =>
    AuthStoreBackend.of({
      get: (key) =>
        state.storage
          .get(key)
          .pipe(
            Effect.mapError(() => AuthStoreError.make({ message: "Auth store storage failed" })),
          ),
      put: (key, value) =>
        state.storage
          .put(key, value)
          .pipe(
            Effect.mapError(() => AuthStoreError.make({ message: "Auth store storage failed" })),
          ),
      remove: (key) =>
        state.storage.delete(key).pipe(
          Effect.asVoid,
          Effect.mapError(() => AuthStoreError.make({ message: "Auth store storage failed" })),
        ),
    }),
  ),
);

// Expected auth failures travel inside the RPC success schemas; infrastructure
// failures become defects and surface as transport errors on the caller side.
const AuthStoreLive = AuthStore.layerBackend.pipe(Layer.provide(BackendLive));

const AuthStoreDurableObjectOptions = {
  rpc: {
    issueChallenge: (input) =>
      Effect.gen(function* () {
        const store = yield* AuthStore;

        return yield* store.issueChallenge(input).pipe(
          Effect.as(null),
          Effect.catchTags({
            AuthRateLimited: (error) => Effect.succeed(error),
            AuthStoreError: Effect.die,
          }),
        );
      }),
    consumeChallenge: (input) =>
      Effect.gen(function* () {
        const store = yield* AuthStore;

        return yield* store.consumeChallenge(input).pipe(
          Effect.catchTags({
            EmailOtpRejected: (error) => Effect.succeed(error),
            AuthStoreError: Effect.die,
          }),
        );
      }),
    issueRegistration: (input) =>
      Effect.gen(function* () {
        const store = yield* AuthStore;

        yield* store.issueRegistration(input).pipe(Effect.catchTag("AuthStoreError", Effect.die));

        return null;
      }),
    inspectRegistration: (tokenDigest: TokenDigestType) =>
      Effect.gen(function* () {
        const store = yield* AuthStore;

        return yield* store.inspectRegistration(tokenDigest).pipe(
          Effect.catchTags({
            InvalidRegistration: (error) => Effect.succeed(error),
            AuthStoreError: Effect.die,
          }),
        );
      }),
    consumeRegistration: (input) =>
      Effect.gen(function* () {
        const store = yield* AuthStore;

        return yield* store.consumeRegistration(input).pipe(
          Effect.as(null),
          Effect.catchTags({
            InvalidRegistration: (error) => Effect.succeed(error),
            AuthStoreError: Effect.die,
          }),
        );
      }),
  },
} satisfies DurableObject.Options<AuthStore, typeof AuthStoreObject>;

/** Builds the auth store object with an application-owned OTLP telemetry layer. */
export const makeAuthStoreDurableObject = (
  telemetry: Layer.Layer<OtlpExporter.Flusher, never, DurableObjectState.DurableObjectState>,
) => AuthStoreObject.make(Layer.merge(AuthStoreLive, telemetry), AuthStoreDurableObjectOptions);

const clientUnavailable = () => AuthStoreError.unavailable;

/**
 * Worker-side `AuthStore` over the auth Durable Object binding. Swapping this
 * layer for a different backing (Postgres, PlanetScale) is the intended
 * migration path: implement the same `AuthStore` contract and rerun the
 * conformance suite.
 */
export const layerAuthStoreClient: Layer.Layer<AuthStore, never, AuthStoreObject> = Layer.effect(
  AuthStore,
)(
  Effect.map(AuthStoreObject, (objects) => {
    const stub = objects.byName("primary");

    return AuthStore.of({
      issueChallenge: Effect.fn("AuthStoreObject.client.issueChallenge")(function* (input) {
        const outcome = yield* stub.issueChallenge(input).pipe(Effect.mapError(clientUnavailable));

        if (outcome !== null) {
          return yield* outcome;
        }
      }),
      consumeChallenge: Effect.fn("AuthStoreObject.client.consumeChallenge")(function* (input) {
        const outcome = yield* stub
          .consumeChallenge(input)
          .pipe(Effect.mapError(clientUnavailable));

        if ("_tag" in outcome) {
          return yield* outcome;
        }

        return outcome;
      }),
      issueRegistration: Effect.fn("AuthStoreObject.client.issueRegistration")(function* (input) {
        yield* stub.issueRegistration(input).pipe(Effect.mapError(clientUnavailable));
      }),
      inspectRegistration: Effect.fn("AuthStoreObject.client.inspectRegistration")(
        function* (tokenDigest) {
          const outcome = yield* stub
            .inspectRegistration(tokenDigest)
            .pipe(Effect.mapError(clientUnavailable));

          if ("_tag" in outcome) {
            return yield* outcome;
          }

          return outcome;
        },
      ),
      consumeRegistration: Effect.fn("AuthStoreObject.client.consumeRegistration")(
        function* (input) {
          const outcome = yield* stub
            .consumeRegistration(input)
            .pipe(Effect.mapError(clientUnavailable));

          if (outcome !== null) {
            return yield* outcome;
          }
        },
      ),
    });
  }),
);

/**
 * Everything the worker needs for a Durable-Object-backed `AuthStore`: the
 * client layer wired to the given binding. The binding name is an intrinsic
 * deployment definition, matching the `durable_objects` entry in the wrangler
 * configuration.
 */
export const layerAuthStore = (options: {
  readonly binding: string;
}): Layer.Layer<
  AuthStore,
  Binding.BindingNotFoundError | Binding.BindingValidationError,
  Environment.WorkerEnvironment
> => layerAuthStoreClient.pipe(Layer.provide(AuthStoreObject.layer({ binding: options.binding })));

// --- Email delivery ------------------------------------------------------------

/** Send Email binding used by {@link layerEmailOtpSender}. */
export class AuthEmail extends Email.Tag<AuthEmail>()("effect-auth/AuthEmail") {}

/** Input handed to a {@link layerEmailOtpSender} content renderer. */
export interface EmailOtpContentInput {
  readonly code: string;
  readonly minutesRemaining: number;
}

/** A rendered OTP message for {@link layerEmailOtpSender}. */
export interface EmailOtpContent {
  readonly subject: string;
  readonly text: string;
  /** HTML alternative to `text`; clients that render HTML prefer it. */
  readonly html?: string;
  /** Attachments, e.g. `cid:`-referenced inline images used by `html`. */
  readonly attachments?: ReadonlyArray<Email.EmailAttachment>;
}

/**
 * `EmailOtpSender` over a Cloudflare Send Email binding. The consumer owns the
 * sending domain (Email Routing must be configured for `from`); message
 * wording can be overridden through `content`.
 *
 * Delivery runs past the response via `waitUntil`: the provider call is the
 * slow part of an OTP request (routinely multiple seconds), and by the time
 * the sender runs the challenge is already persisted, so the endpoint's 202
 * honestly means "accepted". The trade is that a failed send can no longer
 * surface to the caller; the structured delivery-failure log is the only
 * signal.
 */
export const layerEmailOtpSender = (options: {
  /** `send_email` binding name from the wrangler configuration. */
  readonly binding: string;
  /**
   * Verified sender address on a domain with Email Routing enabled. Pass an
   * object to attach a display name.
   */
  readonly from: string | Email.EmailAddress;
  readonly content?: (input: EmailOtpContentInput) => EmailOtpContent;
}): Layer.Layer<
  EmailOtpSender,
  Binding.BindingNotFoundError | Binding.BindingValidationError,
  Environment.WorkerEnvironment | Worker.WorkerContext
> =>
  Layer.effect(EmailOtpSender)(
    Effect.gen(function* () {
      const email = yield* AuthEmail;
      const context = yield* Worker.WorkerContext;

      return EmailOtpSender.of({
        send: Effect.fn("EmailOtpSender.sendEmail")(function* (message) {
          const now = yield* DateTime.now;

          const minutesRemaining = Math.max(
            1,
            Math.round(
              Duration.toMinutes(
                Duration.millis(
                  DateTime.toEpochMillis(message.expiresAt) - DateTime.toEpochMillis(now),
                ),
              ),
            ),
          );

          const code = Redacted.value(message.code);

          const rendered: EmailOtpContent = options.content?.({ code, minutesRemaining }) ?? {
            subject: "Your sign-in code",
            text: `Your sign-in code is ${code}. It expires in ${minutesRemaining} minute${
              minutesRemaining === 1 ? "" : "s"
            }. If you did not request it, ignore this email.`,
          };

          yield* context.waitUntil(
            email
              .send({
                from: options.from,
                to: message.email,
                subject: rendered.subject,
                text: rendered.text,
                ...(rendered.html === undefined ? {} : { html: rendered.html }),
                ...(rendered.attachments === undefined
                  ? {}
                  : { attachments: [...rendered.attachments] }),
              })
              .pipe(
                Effect.asVoid,
                // Delivery happens after the response, so this log is all an
                // undeliverable address leaves behind. Provider reasons are
                // operational and permanent — a suppressed recipient stays
                // suppressed — so record enough to act on. Only the provider's
                // own code and message are logged; the rendered message, which
                // carries the code, never is.
                Effect.tapError((error) =>
                  Effect.logError("Sign-in code delivery failed", {
                    code: Reflect.get(error, "code"),
                    reason: String(Reflect.get(error, "cause") ?? error),
                  }),
                ),
                // Logged above; a second generic waitUntil log adds nothing.
                Effect.catch(() => Effect.void),
              ),
          );
        }),
      });
    }),
  ).pipe(Layer.provide(AuthEmail.layer({ binding: options.binding })));
