import { PasswordHashing } from "@yielded/auth/Password";
import { digest } from "@yielded/auth/Persistence";
import { PhoneCustody } from "@yielded/auth/PhoneOtp";
import * as Drizzle from "drizzle-orm/effect-sqlite-bun";
import { Effect, Redacted, Schema } from "effect";

import { AppAuth } from "./auth";
import { customers, storage } from "./schema";

export const customerId = "customer-001";
export const email = "dan@example.invalid";
export const phoneNumber = "+12025550123";
export const password = "A long example passphrase for this customer";

// Trusted pre-existing credentials, only for this disposable example. Runtime
// enrollment must establish custody and advance revisions in the same transaction.
export const seed = Effect.gen(function* () {
  const database = yield* Drizzle.makeWithDefaults({});
  const verifier = yield* (yield* PasswordHashing).hash(Redacted.make(password));
  const tables = storage.schema;

  yield* database.transaction((tx) =>
    Effect.gen(function* () {
      yield* tx.insert(customers).values({
        id: customerId,
        enabled: true,
        securityRevision: "customer-r1",
        displayName: "Dan",
      });
      yield* tx.insert(tables.identifiers).values({
        namespace: "email",
        value: email,
        subjectId: customerId,
        revision: "email-r1",
        verifiedAt: 1,
        active: true,
      });
      yield* tx.insert(tables.identifiers).values({
        namespace: "phone",
        value: phoneNumber,
        subjectId: customerId,
        revision: "phone-r1",
        verifiedAt: 1,
        active: true,
      });
      yield* tx.insert(tables.credentials).values({
        credentialId: "password-001",
        subjectId: customerId,
        revision: "password-r1",
        active: true,
      });
      yield* tx.insert(tables.credentials).values({
        credentialId: "phone-001",
        subjectId: customerId,
        revision: "phone-r1",
        active: true,
      });
      yield* tx.insert(tables.passwords).values({
        moduleId: AppAuth.strategies.password.persistence.moduleId,
        subjectId: customerId,
        credentialId: "password-001",
        credentialRevision: "password-r1",
        verifierVersion: "verifier-r1",
        verifier: Redacted.value(verifier),
        normalization: "none",
      });

      const moduleId = AppAuth.strategies.phone.persistence.moduleId;

      const state = Schema.encodeSync(
        Schema.fromJsonString(Schema.Struct({ moduleId: Schema.String, record: PhoneCustody })),
      )(
        Schema.decodeUnknownSync(Schema.Struct({ moduleId: Schema.String, record: PhoneCustody }))({
          moduleId,
          record: {
            phoneNumber,
            custodyRevision: "phone-r1",
            credentialRevision: "phone-r1",
            verifiedAtMillis: 1,
            subjectId: customerId,
            credentialId: "phone-001",
            state: "verified",
          },
        }),
      );

      const scope = digest(
        Schema.encodeSync(Schema.fromJsonString(Schema.Array(Schema.String)))([
          "effect-auth/phone/v1",
          moduleId,
          "custody",
          phoneNumber,
        ]),
      );

      yield* tx.insert(tables.phoneState).values({ scope, state, version: "phone-state-r1" });
    }),
  );
});
