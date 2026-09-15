import { hasCommitScope } from "@yielded/auth/Hooks";
import { LoginIdentifier } from "@yielded/auth/Identity";
import {
  defaultPasswordMethodPolicy,
  PasswordCredentialSnapshot,
  PasswordHashing,
  PasswordMethodUnsupported,
  PasswordPersistence,
  PasswordRejected,
  PasswordUnavailable,
} from "@yielded/auth/Password";
import { Email, TokenDigest } from "@yielded/auth/Schema";
import {
  AuthenticationAuthority,
  AuthenticationFlowId,
  type AuthenticationEvidence,
} from "@yielded/auth/Sessions";
import { Crypto, DateTime, Effect, Encoding, Layer, Redacted, Schema } from "effect";

import { AppAuth } from "./auth";
import { Username } from "./contract";
import { AccountMethods } from "./methods";

/** Custom public registration and sign-in, with every dependency visible in this Layer. */
export const AccountMethodsLive = Layer.effect(
  AccountMethods,
  Effect.gen(function* () {
    const passwords = yield* AppAuth.strategies.password.Passwords;
    const registration = yield* AppAuth.strategies.password.RegistrationAuthority;
    const persistence = yield* PasswordPersistence;
    const hasher = yield* PasswordHashing;
    const authority = yield* AuthenticationAuthority;
    const claims = yield* AppAuth.strategies.password.ClaimsForPassword;
    const completion = yield* AppAuth.sessions.AuthenticationCompletion;
    const crypto = yield* Crypto.Crypto;
    const moduleId = AppAuth.strategies.password.persistence.moduleId;

    return AccountMethods.of({
      register: Effect.fn("AccountMethods.register")(
        function* (request) {
          // Reuse the library's password policy and planning; account creation remains our authority.
          const plan = yield* passwords.planRegister(request);

          const receipt = yield* plan.commit.pipe(
            Effect.provideService(AppAuth.strategies.password.RegistrationAuthority, registration),
          );

          return yield* receipt.read.pipe(Effect.mapError(() => PasswordUnavailable.make({})));
        },
        Effect.catchTag("HookDenied", () => PasswordRejected.make({})),
      ),
      signIn: Effect.fn("AccountMethods.signIn")(function* (input) {
        if (yield* hasCommitScope) return yield* PasswordMethodUnsupported.make({});
        const email = Schema.decodeOption(Email)(input.login);

        const identifier = LoginIdentifier.make(
          email._tag === "Some"
            ? { namespace: "email", value: email.value }
            : {
                namespace: "username",
                value: yield* Schema.decodeEffect(Username)(input.login).pipe(
                  Effect.mapError(() => PasswordRejected.make({})),
                ),
              },
        );

        const flowId = AuthenticationFlowId.make(
          yield* crypto.randomUUIDv4.pipe(Effect.mapError(() => PasswordUnavailable.make({}))),
        );

        const admission = yield* persistence
          .admitAttempt(
            {
              moduleId,
              action: "sign-in",
              identifier,
              policy: defaultPasswordMethodPolicy.attempts,
            },
            (value, journal) => journal.prepare(value),
          )
          .pipe(
            Effect.flatMap((receipt) => receipt.read),
            Effect.mapError(() => PasswordUnavailable.make({})),
          );

        if (admission._tag === "Denied") {
          yield* hasher.dummy(input.password).pipe(Effect.ignore);

          return yield* PasswordRejected.make({});
        }

        const captured =
          admission.credential === undefined
            ? undefined
            : yield* Schema.decodeEffect(Schema.toType(PasswordCredentialSnapshot))(
                admission.credential,
              ).pipe(Effect.mapError(() => PasswordUnavailable.make({})));

        const checked = yield* Effect.gen(function* () {
          if (captured === undefined) {
            yield* hasher
              .dummy(input.password)
              .pipe(Effect.mapError(() => PasswordUnavailable.make({})));

            return yield* PasswordRejected.make({});
          }

          const original = yield* authority
            .capture(captured.revision.subjectId, [captured.credentialId])
            .pipe(Effect.mapError(() => PasswordRejected.make({})));

          if (
            original.securityRevision !== captured.revision.securityRevision ||
            !original.credentials.some(
              (item) =>
                item.credentialId === captured.credentialId &&
                item.revision === captured.credentialRevision,
            )
          ) {
            yield* hasher.dummy(input.password).pipe(Effect.ignore);

            return yield* PasswordRejected.make({});
          }
          const raw = Redacted.value(input.password);

          const password =
            captured.normalization === "NFC" ? Redacted.make(raw.normalize("NFC")) : input.password;

          const result = yield* hasher.verify(password, captured.verifier).pipe(
            Effect.catchTag("PasswordVerifierInvalid", () =>
              hasher.dummy(password).pipe(Effect.andThen(PasswordRejected.make({}))),
            ),
            Effect.mapError((error) =>
              Schema.is(PasswordRejected)(error) ? error : PasswordUnavailable.make({}),
            ),
          );

          if (!result.matches) return yield* PasswordRejected.make({});
          const verifiedAt = yield* DateTime.now;

          const rehash = result.needsRehash
            ? {
                expectedVersion: captured.verifierVersion,
                expectedVerifier: captured.verifier,
                nextVerifier: yield* hasher
                  .hash(password)
                  .pipe(Effect.mapError(() => PasswordUnavailable.make({}))),
              }
            : undefined;

          const binding = yield* Schema.encodeEffect(
            Schema.fromJsonString(Schema.Array(Schema.String)),
          )(["customers/sign-in", moduleId, flowId, identifier.namespace, identifier.value]).pipe(
            Effect.mapError(() => PasswordUnavailable.make({})),
          );

          const digest = yield* crypto
            .digest("SHA-256", new TextEncoder().encode(binding))
            .pipe(Effect.mapError(() => PasswordUnavailable.make({})));

          const evidence: AuthenticationEvidence = {
            revision: original,
            flowId,
            bindingDigest: TokenDigest.make(Encoding.encodeBase64Url(digest)),
            proofs: [
              {
                method: "password",
                credentialId: captured.credentialId,
                factors: ["knowledge"],
                userVerified: false,
                phishingResistant: false,
                verifiedAt,
              },
            ],
          };

          return { evidence, credential: captured, rehash };
        }).pipe(Effect.result);

        // Even failed verification settles once. Abandoned attempts keep their admission charge.
        const decision = yield* persistence
          .settleAttempt(
            {
              moduleId,
              attemptId: admission.attemptId,
              ...(captured === undefined ? {} : { captured }),
              outcome: checked._tag === "Success" ? "verified" : "rejected",
              ...(checked._tag === "Success" && checked.success.rehash !== undefined
                ? { rehash: checked.success.rehash }
                : {}),
            },
            (value, journal) => journal.prepare(value),
          )
          .pipe(
            Effect.flatMap((receipt) => receipt.read),
            Effect.mapError(() => PasswordUnavailable.make({})),
          );

        if (checked._tag === "Failure") return yield* checked.failure;
        if (decision !== "verified") return yield* PasswordRejected.make({});
        const values = yield* claims.resolve(checked.success.credential);

        return yield* completion
          .prepare({ evidence: checked.success.evidence, claims: values })
          .pipe(
            Effect.flatMap((receipt) => receipt.read),
            Effect.mapError((error) =>
              Schema.is(PasswordRejected)(error) ? error : PasswordUnavailable.make({}),
            ),
          );
      }),
    });
  }),
);
