import { Context, Effect, Layer, Option } from "effect";

import type { AuthStoreError } from "../Errors";
import type { SubjectId } from "../Schema";
import type { OAuthConnection, OAuthProviderKey } from "./schema";

/**
 * Consumer-implemented persistence for provider connections, keyed by
 * `(provider, subjectId)`. This is the package's explicit token-persistence
 * boundary:
 *
 * - **Production adapters MUST encrypt the token values at rest.** The
 *   `OAuthConnection` token fields are `Redacted`; an adapter unwraps them
 *   with `Redacted.value` only inside its encryption boundary and re-wraps on
 *   read. Storing the unwrapped values verbatim is a security defect.
 * - Token values must never appear in logs, errors, or telemetry; the
 *   `Redacted` wrapper protects accidental stringification, nothing more.
 * - `put` replaces any existing connection for the same key.
 */
export class OAuthConnectionStore extends Context.Service<
  OAuthConnectionStore,
  {
    readonly get: (
      provider: OAuthProviderKey,
      subjectId: SubjectId,
    ) => Effect.Effect<Option.Option<OAuthConnection>, AuthStoreError>;
    readonly put: (connection: OAuthConnection) => Effect.Effect<void, AuthStoreError>;
    readonly remove: (
      provider: OAuthProviderKey,
      subjectId: SubjectId,
    ) => Effect.Effect<void, AuthStoreError>;
  }
>()("effect-auth/OAuthConnectionStore") {
  /**
   * In-memory adapter for tests and local development; never durable and
   * never encrypted, so never a production adapter.
   */
  static readonly layerMemory: Layer.Layer<OAuthConnectionStore> = Layer.sync(OAuthConnectionStore)(
    () => {
      const connections = new Map<string, OAuthConnection>();
      const key = (provider: OAuthProviderKey, subjectId: SubjectId) => `${provider}|${subjectId}`;

      return OAuthConnectionStore.of({
        get: (provider, subjectId) =>
          Effect.sync(() => Option.fromNullishOr(connections.get(key(provider, subjectId)))),

        put: (connection) =>
          Effect.sync(() => {
            connections.set(key(connection.provider, connection.subjectId), connection);
          }),

        remove: (provider, subjectId) =>
          Effect.sync(() => {
            connections.delete(key(provider, subjectId));
          }),
      });
    },
  );
}
