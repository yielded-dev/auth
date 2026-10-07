import { OAuthServer } from "@yielded/auth";
import { OAuthServerPersistence } from "@yielded/auth-persistence";
import { DateTime, Effect, Layer, Redacted } from "effect";
import { HttpServerRequest } from "effect/http";
import { SqlClient } from "effect/sql";

import { SettingsAuth } from "./oauth-settings-auth";

export const yielded = OAuthServer.makeOpenId("yielded");

export const YieldedGrantsLive = OAuthServerPersistence.layer.pipe(
  Layer.provideMerge(
    Layer.effectDiscard(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;

        // Reuse the adapter's standalone CAS storage in the application's database.
        for (const migration of OAuthServerPersistence.migrations)
          yield* sql.unsafe(migration.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS"));
      }),
    ),
  ),
);

export const identityLayer = (cookieName: string, displayName: string) =>
  Layer.effect(
    yielded.Identity,
    Effect.gen(function* () {
      const auth = yield* SettingsAuth;
      const sql = yield* SqlClient.SqlClient;

      return yielded.Identity.of({
        current: Effect.gen(function* () {
          const request = yield* HttpServerRequest.HttpServerRequest;
          const credential = request.cookies[cookieName];

          if (credential === undefined) return undefined;

          return yield* auth.verifySession(Redacted.make(credential)).pipe(
            Effect.map((session) => ({
              subjectId: session.subjectId,
              sessionId: session.sessionId,
              securityRevision: session.securityRevision,
              authenticatedAtMillis: DateTime.toEpochMillis(session.assurance.authenticatedAt),
              expiresAtMillis: DateTime.toEpochMillis(session.expiresAt),
            })),
            Effect.catchTag("SessionInvalid", () => Effect.succeed(undefined)),
            Effect.mapError(() => OAuthServer.Unavailable.make({})),
          );
        }),
        active: Effect.fn("YieldedIdentity.active")(
          function* (authentication) {
            const rows = yield* sql`SELECT id FROM oauth_subject s
        WHERE s.id = ${authentication.subjectId} AND s.status = 'active'
        AND s.${sql("securityRevision")} = ${authentication.securityRevision}
        AND NOT EXISTS (SELECT 1 FROM oauth_settings_revocation r
          WHERE r.module_id = ${SettingsAuth.sessions.moduleId}
          AND r.subject_id = s.id AND r.session_id = ${authentication.sessionId})`;

            return rows.length === 1;
          },
          Effect.mapError(() => OAuthServer.Unavailable.make({})),
        ),
        profile: () => Effect.succeed({ name: displayName }),
      });
    }),
  );
