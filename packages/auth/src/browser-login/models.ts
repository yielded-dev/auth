import { Context, type Effect, Schema } from "effect";

import { credentialSlots } from "../http-operation/models";

export class Invalid extends Schema.TaggedError<Invalid>()("BrowserLoginInvalid", {}) {}
export class Unavailable extends Schema.TaggedError<Unavailable>()("BrowserLoginUnavailable", {}) {}

export class ConfigurationError extends Schema.TaggedError<ConfigurationError>()(
  "BrowserLoginConfigurationError",
  {},
) {}

/** An exchange may have issued a session. Never repeat issuance for this attempt. */
export class Indeterminate extends Schema.TaggedError<Indeterminate>()(
  "BrowserLoginIndeterminate",
  {},
) {}

export class PlatformError extends Schema.TaggedError<PlatformError>()(
  "BrowserLoginPlatformError",
  {
    reason: Schema.Literals(["unavailable", "cancelled", "busy", "callback", "storage", "expired"]),
  },
) {}

export const Random = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/));
export const ClientId = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9._-]{1,128}$/));
const UrlText = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(2048));

/** Exact, pre-registered URL. No query, fragment, credentials, or ambiguous URL spelling. */
export const ReturnUrl = UrlText.check(
  Schema.makeFilter((text) => {
    try {
      const url = new URL(text);

      return (
        url.href === text &&
        !url.username &&
        !url.password &&
        !url.search &&
        !url.hash &&
        !/[\s\\?#]/.test(text) &&
        (url.protocol === "https:" || /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/.test(url.protocol))
      );
    } catch {
      return false;
    }
  }),
);

export const HostedUrl = UrlText.check(
  Schema.makeFilter((text) => {
    try {
      const url = new URL(text);

      return (
        url.href === text &&
        !url.username &&
        !url.password &&
        !url.search &&
        !url.hash &&
        (url.protocol === "https:" ||
          (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
      );
    } catch {
      return false;
    }
  }),
);

export const Client = Schema.Struct({
  clientId: ClientId,
  returnUrl: ReturnUrl,
  /** Both policies require a visible confirmation naming the account and native app. */
  browserSession: Schema.Literals(["confirm", "reauthenticate"]),
});

export type Client = typeof Client.Type;

export const Initiate = Schema.Struct({
  clientId: ClientId,
  returnUrl: ReturnUrl,
  state: Random,
  challenge: Random,
});

export const Started = Schema.Struct({ attemptId: Random, expiresAtMillis: Schema.Natural });

export const Binding = Schema.Struct({
  attemptId: Random,
  clientId: ClientId,
  verifier: Schema.RedactedFromValue(Random),
});

export const Status = Schema.Struct({
  status: Schema.Literals([
    "Waiting",
    "Authorized",
    "Exchanging",
    "Complete",
    "Cancelled",
    "Expired",
  ]),
  sessionId: Schema.optionalKey(Schema.NonEmptyString),
});

/** Private host custody. Save Exchanging durably BEFORE dispatching exchange. */
export const Attempt = Schema.Struct({
  ...Started.fields,
  clientId: ClientId,
  returnUrl: ReturnUrl,
  state: Random,
  verifier: Schema.RedactedFromValue(Random),
  phase: Schema.Literals(["Waiting", "Exchanging"]),
});

export type Attempt = typeof Attempt.Type;

/** Canonical private platform vault format. Adapters supply encryption and
 * atomic custody; credentials and exchange fences share one stored value. */
export const VaultRecord = Schema.Struct({
  attempt: Schema.optionalKey(Attempt),
  credentials: Schema.Record(
    Schema.Literals(credentialSlots),
    Schema.optionalKey(
      Schema.Struct({
        credential: Schema.RedactedFromValue(
          Schema.NonEmptyString.check(Schema.isMaxLength(16384)),
        ),
        expiresAtMillis: Schema.Natural,
      }),
    ),
  ),
});

/** Private source is schema-encoded by the owning session module; never a bearer. */
export const Record = Schema.Struct({
  ...Initiate.fields,
  version: Random,
  createdAtMillis: Schema.Natural,
  expiresAtMillis: Schema.Natural,
  status: Schema.Literals(["Waiting", "Authorized", "Exchanging", "Complete", "Cancelled"]),
  codeDigest: Schema.optionalKey(Random),
  source: Schema.optionalKey(Schema.Json),
  sessionId: Schema.optionalKey(Schema.NonEmptyString),
});

export type Record = typeof Record.Type;

/** Linearizable standalone commits; retain terminal records until expiry. An
 * uncertain insert/CAS fails Unavailable and MUST NOT be retried by the adapter.
 * CAS must check version AND expiry against its commit clock. A successful
 * Exchanging transition is terminal for issuance, even if the process crashes.
 */
export class Persistence extends Context.Service<
  Persistence,
  {
    readonly get: (namespace: string, id: string) => Effect.Effect<Record | undefined, Unavailable>;
    readonly insert: (
      namespace: string,
      id: string,
      record: Record,
    ) => Effect.Effect<boolean, Unavailable>;
    readonly compareAndSet: (
      namespace: string,
      id: string,
      version: string,
      record: Record,
    ) => Effect.Effect<boolean, Unavailable>;
  }
>()("effect-auth/BrowserLogin/Persistence") {}
