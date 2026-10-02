import * as BrowserLogin from "@yielded/auth/BrowserLogin";
import { OperationHttpError } from "@yielded/auth/OperationHttp";
import type { NativeCredentials } from "@yielded/auth/OperationHttpClient";
import type { CredentialSlot } from "@yielded/auth/Operations";
import { DateTime, Effect, Layer, type Redacted, Schema, Semaphore } from "effect";
import { Platform } from "react-native";
import { InAppBrowser } from "react-native-inappbrowser-reborn";
import * as Keychain from "react-native-keychain";

const failure = (reason: BrowserLogin.PlatformError["reason"]) =>
  BrowserLogin.PlatformError.make({ reason });

const environment = Effect.try({
  try: () => Platform.OS === "ios" && Number.parseInt(String(Platform.Version), 10) >= 16,
  catch: () => failure("unavailable"),
}).pipe(
  Effect.flatMap((supported) => (supported ? Effect.void : Effect.fail(failure("unavailable")))),
);

const openInput = Schema.Struct({
  url: Schema.String.check(
    Schema.isMinLength(1),
    Schema.isMaxLength(4096),
    Schema.makeFilter((text) => {
      try {
        const url = new URL(text);

        return (
          url.href === text &&
          url.protocol === "https:" &&
          !url.username &&
          !url.password &&
          !url.hash
        );
      } catch {
        return false;
      }
    }),
  ),
  // This peer uses callbackURLScheme, not Apple's HTTPS callback API.
  returnUrl: BrowserLogin.ReturnUrl.check(Schema.makeFilter((text) => !text.startsWith("https:"))),
  ephemeral: Schema.Boolean,
});

const browserResult = Schema.Union([
  Schema.Struct({
    type: Schema.Literal("success"),
    url: Schema.String.check(Schema.isMaxLength(8192)),
  }),
  Schema.Struct({ type: Schema.Literals(["cancel", "dismiss"]) }),
]);

interface Lease {
  started: boolean;
  settled: boolean;
  listening: boolean;
}

// The bridge owns a single native resolver. All Layers in this installed module
// share admission; applications must not call the peer independently.
let activeBrowser: Lease | undefined;

const settle = (lease: Lease) => {
  lease.settled = true;
  if (activeBrowser === lease) activeBrowser = undefined;
};

const acquireBrowser = Effect.sync(() => {
  if (activeBrowser !== undefined) return undefined;
  const lease: Lease = { started: false, settled: false, listening: true };

  activeBrowser = lease;

  return lease;
}).pipe(
  Effect.flatMap((lease) =>
    lease === undefined ? Effect.fail(failure("busy")) : Effect.succeed(lease),
  ),
);

const releaseBrowser = (lease: Lease) =>
  Effect.sync(() => {
    lease.listening = false;
    if (!lease.started) settle(lease);
    if (lease.settled) return;
    try {
      InAppBrowser.closeAuth();
    } catch {
      // Dismissal is best-effort. Keep admission held until native settlement even
      // if dismissal fails; never deliver a late callback to another attempt.
    }
  });

const prompt = (lease: Lease, input: typeof openInput.Type) =>
  Effect.callback<unknown, BrowserLogin.PlatformError>((resume, signal) => {
    lease.started = true;
    try {
      void InAppBrowser.openAuth(input.url, input.returnUrl, {
        ephemeralWebSession: input.ephemeral,
      }).then(
        (value: unknown) => {
          settle(lease);
          if (lease.listening && !signal.aborted) resume(Effect.succeed(value));
        },
        () => {
          settle(lease);
          if (lease.listening && !signal.aborted) resume(Effect.fail(failure("unavailable")));
        },
      );
    } catch {
      settle(lease);
      resume(Effect.fail(failure("unavailable")));
    }
  });

/** iOS 16+ ASWebAuthenticationSession. Each open owns its Scope and dismissal;
 * interruption retains the shared busy guard until the native promise settles. */
export const layerBrowser = Layer.succeed(
  BrowserLogin.Browser,
  BrowserLogin.Browser.of({
    open: Effect.fnUntraced(function* (input) {
      yield* environment;

      const request = yield* Schema.decodeEffect(openInput)(input).pipe(
        Effect.mapError(() => failure("callback")),
      );

      return yield* Effect.scoped(
        Effect.gen(function* () {
          const lease = yield* Effect.acquireRelease(acquireBrowser, releaseBrowser);

          const available = yield* Effect.tryPromise({
            try: () => InAppBrowser.isAvailable(),
            catch: () => failure("unavailable"),
          });

          if (!available) return yield* failure("unavailable");

          const result = yield* Schema.decodeUnknownEffect(browserResult)(
            yield* prompt(lease, request),
          ).pipe(Effect.mapError(() => failure("callback")));

          if (result.type !== "success") return yield* failure("cancelled");

          // The OS matches the scheme only. Bind the full callback target here;
          // core owns state/code validation and the exchange decision.
          return yield* Schema.decodeEffect(
            Schema.String.check(
              Schema.makeFilter((text) => {
                try {
                  const url = new URL(text);

                  if (url.href !== text || url.username || url.password || url.hash) return false;
                  url.search = "";

                  return url.href === request.returnUrl;
                } catch {
                  return false;
                }
              }),
            ),
          )(result.url).pipe(Effect.mapError(() => failure("callback")));
        }),
      );
    }),
  }),
);

const slots = [
  "session",
  "pending-proof",
  "proof-continuation",
  "registration",
  "request-binding",
  "session-step-up",
  "password-intent",
] as const satisfies ReadonlyArray<CredentialSlot>;

const vaultRecord = BrowserLogin.VaultRecord;

const vaultJson = Schema.fromJsonString(vaultRecord);

const keychainResult = Schema.Union([
  Schema.Literal(false),
  Schema.Struct({ password: Schema.String.check(Schema.isMaxLength(1048576)) }),
]);

/** Use a distinct service per application, server environment and client ID.
 * Build this Layer once per authentication lifetime; no other process or Layer
 * may write this Keychain service. Keychain has no cross-process CAS contract. */
export const layerVault = (options: { readonly service: string }) =>
  Layer.effect(
    BrowserLogin.Vault,
    Effect.gen(function* () {
      yield* environment;

      const service = yield* Schema.decodeEffect(
        Schema.NonEmptyString.check(Schema.isMaxLength(256)),
      )(options.service).pipe(Effect.mapError(() => failure("storage")));

      const keychainOptions = {
        service,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        cloudSync: false,
      };

      const gate = yield* Semaphore.make(1);

      const readRecord: Effect.Effect<typeof vaultRecord.Type, BrowserLogin.PlatformError> =
        Effect.gen(function* () {
          const result = yield* Effect.tryPromise({
            try: () => Keychain.getGenericPassword(keychainOptions),
            catch: () => failure("storage"),
          }).pipe(
            Effect.flatMap(Schema.decodeUnknownEffect(keychainResult)),
            Effect.mapError(() => failure("storage")),
          );

          if (result === false) return { credentials: {} } satisfies typeof vaultRecord.Type;

          return yield* Schema.decodeEffect(vaultJson)(result.password, {
            onExcessProperty: "error",
          }).pipe(Effect.mapError(() => failure("storage")));
        });

      const writeRecord = Effect.fnUntraced(function* (record: typeof vaultRecord.Type) {
        const encoded = yield* Schema.encodeEffect(vaultJson)(record).pipe(
          Effect.mapError(() => failure("storage")),
        );

        const result = yield* Effect.tryPromise({
          try: () => Keychain.setGenericPassword("yielded-auth", encoded, keychainOptions),
          catch: () => failure("storage"),
        });

        if (result === false) return yield* failure("storage");
      });

      // Keychain promises are not cancellable. Admitted operations must settle
      // before releasing this gate or acknowledging an Exchanging checkpoint.
      const locked = <A, E>(work: Effect.Effect<A, E>) =>
        gate.withPermits(1)(Effect.uninterruptible(work));

      const read: NativeCredentials["read"] = locked(
        Effect.gen(function* () {
          const record = yield* readRecord;
          const now = DateTime.toEpochMillis(yield* DateTime.now);
          const credentials: Partial<Record<CredentialSlot, Redacted.Redacted<string>>> = {};

          for (const slot of slots) {
            const value = record.credentials[slot];

            if (value !== undefined && value.expiresAtMillis > now)
              credentials[slot] = value.credential;
          }

          return credentials;
        }),
      ).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "credentials" })));

      const accept: NativeCredentials["accept"] = (commands) =>
        locked(
          Effect.gen(function* () {
            const record = yield* readRecord;
            const credentials = { ...record.credentials };

            for (const command of commands) {
              if (command._tag === "Clear") delete credentials[command.slot];
              else
                credentials[command.slot] = {
                  credential: command.credential,
                  expiresAtMillis: command.expiresAtMillis,
                };
            }
            yield* writeRecord({ ...record, credentials });
          }),
        ).pipe(Effect.mapError(() => OperationHttpError.make({ reason: "credentials" })));

      return BrowserLogin.Vault.of({
        read,
        accept,
        loadAttempt: locked(readRecord.pipe(Effect.map((record) => record.attempt))),
        saveAttempt: (attempt) =>
          locked(
            Effect.gen(function* () {
              const record = yield* readRecord;

              yield* writeRecord(
                attempt === undefined
                  ? { credentials: record.credentials }
                  : { ...record, attempt },
              );
            }),
          ),
      });
    }),
  );
