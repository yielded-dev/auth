import { PasskeyConfig, PasskeyUnavailable } from "@yielded/auth/Passkey";
import { layerSimpleWebAuthnPasskeyProtocol } from "@yielded/auth/PasskeySimpleWebAuthn";
import {
  defaultPasswordPolicy,
  NewPasswordCheck,
  PasswordPersistence,
  PasswordUnavailable,
} from "@yielded/auth/Password";
import { SubjectId } from "@yielded/auth/Schema";
import { SessionInvalid, SessionUnavailable } from "@yielded/auth/Sessions";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { eq } from "drizzle-orm";
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Crypto, Effect, Layer, Option, Schema } from "effect";

import { AppAuth } from "../../shared/account/auth";
import { Claims, minimumPasswordLength } from "../../shared/account/contract";
import { HashingLive } from "../../shared/account/hashing";
import { MigrationsLive } from "./migrations";
import { ActionPoliciesLive } from "./policy";
import { customers, Persistence, storage } from "./schema";

// The application's versioned migrations own every table. Auth starts afterward.
export const DatabaseReady = MigrationsLive.pipe(
  Layer.provideMerge(Persistence.Config.layer(storage)),
);

const ProvisioningLive = Layer.effect(
  Persistence.Provisioning,
  Effect.gen(function* () {
    const database = yield* Drizzle.makeWithDefaults({});
    const crypto = yield* Crypto.Crypto;

    return {
      password: Effect.fn("Customers.create")(
        function* ({ registration }) {
          const id = yield* crypto.randomUUIDv4;
          const revision = yield* crypto.randomUUIDv4;

          // Drizzle joins the Effect SQL transaction owned by AuthPersistence.
          yield* database.insert(customers).values({
            id,
            enabled: true,
            securityRevision: revision,
            displayName: registration.displayName,
          });

          return yield* Schema.decodeUnknownEffect(SubjectId)(id);
        },
        Effect.mapError(() => PasswordUnavailable.make({})),
      ),
    };
  }),
).pipe(Layer.provide(layerWebCrypto));

const ClaimsLive = Layer.effect(
  AppAuth.strategies.password.ClaimsForPassword,
  Effect.gen(function* () {
    const database = yield* Drizzle.makeWithDefaults({});

    return {
      resolve: Effect.fn("Customers.claims")(
        function* (credential) {
          const rows = yield* database
            .select()
            .from(customers)
            .where(eq(customers.id, credential.revision.subjectId));

          if (rows.length !== 1 || !rows[0].enabled) return yield* PasswordUnavailable.make({});

          return yield* Schema.decodeUnknownEffect(Claims)({
            displayName: rows[0].displayName,
            email: credential.identifier.value,
            emailVerified: credential.identifierVerifiedAtMillis !== undefined,
          });
        },
        Effect.mapError(() => PasswordUnavailable.make({})),
      ),
    };
  }),
);

const PasskeyClaimsLive = Layer.effect(
  AppAuth.strategies.passkey.ClaimsForPasskey,
  Effect.gen(function* () {
    const passwords = yield* PasswordPersistence;
    const claims = yield* AppAuth.strategies.password.ClaimsForPassword;

    return {
      resolve: Effect.fn("Customers.passkeyClaims")(
        function* (credential) {
          const current = yield* passwords.readForSubject({
            moduleId: AppAuth.strategies.password.persistence.moduleId,
            subjectId: credential.revision.subjectId,
          });

          if (
            Option.isNone(current) ||
            current.value.revision.securityRevision !== credential.revision.securityRevision
          )
            return yield* PasskeyUnavailable.make({});

          return yield* claims.resolve(current.value);
        },
        Effect.mapError(() => PasskeyUnavailable.make({})),
      ),
    };
  }),
).pipe(Layer.provide(ClaimsLive));

// Read current application claims without changing the session's authentication or expiry.
const SessionClaimsLive = Layer.effect(
  AppAuth.sessions.StatefulSessionPersistence,
  Effect.gen(function* () {
    const sessions = yield* AppAuth.sessions.StatefulSessionPersistence;
    const passwords = yield* PasswordPersistence;
    const claims = yield* AppAuth.strategies.password.ClaimsForPassword;

    return {
      ...sessions,
      verify: Effect.fn("Customers.sessionClaims")(
        function* (input) {
          const session = yield* sessions.verify(input);

          const current = yield* passwords.readForSubject({
            moduleId: AppAuth.strategies.password.persistence.moduleId,
            subjectId: session.subjectId,
          });

          if (
            Option.isNone(current) ||
            current.value.revision.subjectId !== session.subjectId ||
            current.value.revision.securityRevision !== session.securityRevision
          )
            return yield* SessionInvalid.make({});

          return { ...session, claims: yield* claims.resolve(current.value) };
        },
        Effect.mapError((error) =>
          Schema.is(SessionInvalid)(error) ? error : SessionUnavailable.make({}),
        ),
      ),
    };
  }),
).pipe(
  Layer.provide(ClaimsLive),
  Layer.provideMerge(Persistence.layer.pipe(Layer.provide(ProvisioningLive))),
);

const ServicesLive = Layer.mergeAll(ClaimsLive, PasskeyClaimsLive, ActionPoliciesLive).pipe(
  Layer.provideMerge(SessionClaimsLive),
);

// The host supplies SQL, delivery, proof keys, and compromised-password screening.
export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(
    NewPasswordCheck.layer({ ...defaultPasswordPolicy, minimumCodePoints: minimumPasswordLength }),
  ),
  Layer.provide(layerSimpleWebAuthnPasskeyProtocol),
  Layer.provide(ServicesLive),
  Layer.provideMerge(DatabaseReady),
  Layer.provideMerge(HashingLive),
  Layer.provide(
    PasskeyConfig.layer({
      id: "localhost",
      name: "Yielded Auth · Example 02",
      origins: ["http://localhost:4182"],
      developmentLocalhost: true,
    }),
  ),
);
