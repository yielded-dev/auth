import { it } from "@effect/vitest";
import { OAuth, Operations } from "@yielded/auth";
import type { CommitJournal } from "@yielded/auth/Hooks";
import { getTableName } from "drizzle-orm";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";
import { expect } from "vite-plus/test";

import { configuration, setup } from "./fixtures/oauth-managed";

const prepare = <A>(value: A, journal: CommitJournal) => journal.prepare(value);

// https://github.com/yielded-dev/auth/issues/306: native flow checks ignored the deployment clock policy.
it.live.each(["sqlite", "d1", "pglite"] as const)(
  "%s OAuth flow tolerance preserves expiry and single consumption",
  (backend) =>
    Effect.gen(function* () {
      for (const futureToleranceMillis of [0, 60_000]) {
        yield* Effect.scoped(
          Effect.gen(function* () {
            const fixture = yield* setup(backend);
            const sql = Context.get(fixture.context, SqlClient.SqlClient);
            const table = sql(getTableName(fixture.table("oauthSignInFlows")));

            const rows = yield* sql.onDialectOrElse({
              pg: () =>
                sql`select floor(extract(epoch from clock_timestamp()) * 1000)::bigint as now`,
              orElse: () => sql`select cast(unixepoch('subsec') * 1000 as integer) as now`,
            });

            const now = Number(rows[0].now);

            for (const [name, issued, expires, expected] of [
              ["within", now + 30_000, now + 240_000, futureToleranceMillis > 0],
              ["excess", now + 120_000, now + 240_000, false],
              ["expired", now - 120_000, now - 30_000, false],
              ["live", now - 30_000, now + 240_000, true],
            ] as const) {
              const flow = yield* Schema.decodeEffect(OAuth.OAuthSignInFlow)({
                context: {
                  ...configuration,
                  responseMode: "query",
                  namespace: "effect-auth/oauth-sign-in-context/v1",
                  moduleId: "strava/oauth",
                  generation: 1,
                  flowId: name,
                  returnTarget: "/activities",
                  stateDigest: name.padEnd(43, "A"),
                  requestBindingVerifier: "B".repeat(43),
                  requestBindingExpiresAtMillis: now + 300_000,
                  issuedAtMillis: issued,
                  expiresAtMillis: expires,
                  exchangeTimeoutMillis: 30_000,
                },
                sealed: {
                  format: "oauth-xchacha20poly1305-v1",
                  keyId: "test",
                  nonce: "A".repeat(32),
                  ciphertext: "A".repeat(22),
                },
              });

              expect(
                (yield* (yield* fixture.signIn.issue(flow, prepare)).read)._tag,
                `${name}/${futureToleranceMillis}`,
              ).toBe(expected ? "Issued" : "Rejected");
              if (!expected) continue;
              const access = { ...flow.context };

              if (name === "live") {
                yield* sql`update ${table} set expires_at = ${now - 1} where flow_id = ${name}`;
                expect((yield* (yield* fixture.signIn.consume(access, prepare)).read)._tag).toBe(
                  "Rejected",
                );

                const expiredBinding = {
                  ...flow.context,
                  requestBindingExpiresAtMillis: OAuth.OAuthInstant.make(now - 1),
                };

                const snapshot = yield* Schema.encodeEffect(
                  Schema.fromJsonString(OAuth.OAuthSignInFlow),
                )({ ...flow, context: expiredBinding });

                yield* sql`update ${table} set expires_at = ${expires}, binder_expires_at = ${expiredBinding.requestBindingExpiresAtMillis}, snapshot = ${snapshot} where flow_id = ${name}`;
                expect(
                  (yield* (yield* fixture.signIn.consume(expiredBinding, prepare)).read)._tag,
                ).toBe("Rejected");
                continue;
              }

              expect((yield* (yield* fixture.signIn.consume(access, prepare)).read)._tag).toBe(
                "Consumed",
              );
              expect((yield* (yield* fixture.signIn.consume(access, prepare)).read)._tag).toBe(
                "Rejected",
              );
            }
            fixture.assertBatchExecution();
          }).pipe(Effect.provideService(Operations.AuthenticationClock, { futureToleranceMillis })),
        );
      }
    }),
  { timeout: 30_000 },
);
