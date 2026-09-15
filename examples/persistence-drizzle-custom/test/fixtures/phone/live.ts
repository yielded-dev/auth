import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { PasswordUnavailable } from "@yielded/auth/Password";
import { PhoneOtpUnavailable } from "@yielded/auth/PhoneOtp";
import { eq } from "drizzle-orm";
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Effect, Layer } from "effect";

import { HashingLive } from "../../../../shared/account/hashing";
import { AppAuth } from "./auth";
import { DeliveryLive } from "./delivery";
import { MigrationsLive } from "./migrations";
import { customers, Persistence, storage } from "./schema";
import { customerId, seed } from "./seed";

const DatabaseLive = SqliteClient.layer({ filename: ":memory:" });
const ConfigLive = Persistence.Config.layer(storage);

// The application migrator owns all tables; the auth migrator is not installed.
const DatabaseReady = MigrationsLive.pipe(
  Layer.provideMerge(ConfigLive),
  Layer.provideMerge(DatabaseLive),
);

const SeededDatabase = Layer.effectDiscard(seed).pipe(
  Layer.provideMerge(DatabaseReady),
  Layer.provideMerge(HashingLive),
);

const ClaimsLive = Layer.unwrap(
  Effect.gen(function* () {
    const database = yield* Drizzle.makeWithDefaults({});

    const claims = (subjectId: string) =>
      database
        .select()
        .from(customers)
        .where(eq(customers.id, subjectId))
        .pipe(
          Effect.flatMap((rows) =>
            rows.length === 1 && rows[0].enabled
              ? Effect.succeed({ displayName: rows[0].displayName })
              : Effect.fail(PasswordUnavailable.make({})),
          ),
          Effect.mapError(() => PasswordUnavailable.make({})),
        );

    return Layer.mergeAll(
      Layer.succeed(AppAuth.strategies.password.ClaimsForPassword, {
        resolve: (credential) => claims(credential.revision.subjectId),
      }),
      Layer.succeed(AppAuth.strategies.phone.ClaimsForPhone, {
        resolve: (credential) =>
          claims(credential.revision.subjectId).pipe(
            Effect.mapError(() => PhoneOtpUnavailable.make({})),
          ),
      }),
    );
  }),
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(Persistence.layer),
  Layer.provide(ClaimsLive),
  Layer.provideMerge(DeliveryLive),
  Layer.provideMerge(SeededDatabase),
);

export const disableCustomer = Effect.gen(function* () {
  const database = yield* Drizzle.makeWithDefaults({});

  yield* database.transaction((tx) =>
    tx
      .update(customers)
      .set({ enabled: false, securityRevision: "customer-r2" })
      .where(eq(customers.id, customerId)),
  );
});
