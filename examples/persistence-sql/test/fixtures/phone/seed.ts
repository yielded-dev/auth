import { PasswordHashing } from "@yielded/auth/Password";
import { digest } from "@yielded/auth/Persistence";
import { PhoneCustody } from "@yielded/auth/PhoneOtp";
import { Effect, Redacted, Schema } from "effect";
import { SqlClient } from "effect/unstable/sql";

import { AppAuth } from "./auth";

export const customerId = "customer-001";
export const email = "dan@example.invalid";
export const phoneNumber = "+12025550123";
export const password = "A long example passphrase for this customer";

// Trusted fixtures, installed atomically in a disposable database.
export const seed = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const active = sql.onDialectOrElse({ pg: () => true, orElse: () => 1 });
  const verifier = yield* (yield* PasswordHashing).hash(Redacted.make(password));
  const moduleId = AppAuth.strategies.phone.persistence.moduleId;
  const State = Schema.Struct({ moduleId: Schema.String, record: PhoneCustody });

  const state = Schema.encodeSync(Schema.fromJsonString(State))(
    Schema.decodeUnknownSync(State)({
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

  yield* sql.withTransaction(
    Effect.gen(function* () {
      yield* sql`insert into customers values (${customerId}, ${active}, 'customer-r1', 'Dan')`;
      yield* sql`insert into app_identifiers values ('email', ${email}, ${customerId}, 'email-r1', 1, ${active})`;
      yield* sql`insert into app_identifiers values ('phone', ${phoneNumber}, ${customerId}, 'phone-r1', 1, ${active})`;
      yield* sql`insert into app_credentials values ('password-001', ${customerId}, 'password-r1', ${active})`;
      yield* sql`insert into app_credentials values ('phone-001', ${customerId}, 'phone-r1', ${active})`;
      yield* sql`insert into app_passwords values (${AppAuth.strategies.password.persistence.moduleId}, ${customerId}, 'password-001', 'password-r1', 'verifier-r1', ${Redacted.value(verifier)}, 'none')`;
      yield* sql`insert into app_phone_state values (${scope}, ${state}, 'phone-state-r1')`;
    }),
  );
});
