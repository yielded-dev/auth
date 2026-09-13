import { it } from "@effect/vitest";
import { Auth, Sessions } from "@yielded/auth";
import { ProofPersistence, SmsProofDelivery } from "@yielded/auth/Proofs";
import { PhoneOtp } from "@yielded/auth/strategies";
import { Effect, Encoding, Layer, Redacted, Schema } from "effect";
import { expect, expectTypeOf } from "vite-plus/test";

const keyring = {
  activeKeyId: "test",
  keys: [{ id: "test", material: Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32))) }],
};

const AppAuth = Auth.make("test/phone-sign-in", {
  claims: Schema.Struct({ name: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: { phone: PhoneOtp.make({ template: "sign-in", keys: keyring }) },
  defaultStrategy: "phone",
});

it.effect(
  "builds sign-in without number management and keeps SMS and request context explicit",
  () =>
    Effect.gen(function* () {
      const networks: string[] = [];

      // Admission rejects before storage or delivery. Unexpected calls to these
      // ports fail loudly; this test only exercises public composition and admission.
      const dependencies = Layer.mergeAll(
        Layer.mock(Sessions.AuthenticationAuthority, {}),
        Layer.mock(AppAuth.sessions.StatefulSessionPersistence, {}),
        Layer.mock(AppAuth.sessions.SessionRepository, {}),
        Layer.mock(ProofPersistence, {}),
        Layer.mock(PhoneOtp.PhoneSignInTargets, {}),
        Layer.mock(PhoneOtp.PhoneDeliveryEligibility, {}),
        Layer.mock(AppAuth.strategies.phone.ClaimsForPhone, {}),
        Layer.mock(PhoneOtp.PhoneAdmission, {
          admit: ({ networkKey }) =>
            Effect.sync(() => {
              networks.push(networkKey);

              return false;
            }),
        }),
        Auth.RequestBindingConfig.layer({ keyring, lifetimeMillis: 60_000, generation: 1 }),
      );

      const withoutSms = AppAuth.layer.pipe(Layer.provide(dependencies));

      expectTypeOf<Layer.Services<typeof withoutSms>>().toEqualTypeOf<SmsProofDelivery>();

      const AuthLive = withoutSms.pipe(
        Layer.provide(
          SmsProofDelivery.layer({ vendorId: "test", idempotencyMillis: 0 }, () =>
            Effect.die("Rejected admission must not send an SMS"),
          ),
        ),
      );

      yield* Effect.gen(function* () {
        const auth = yield* AppAuth;

        expect("begin" in auth).toBe(false);
        expect("completeLifecycle" in auth).toBe(false);

        for (const networkKey of ["network-a", "network-b"]) {
          const result = yield* auth.signIn({ phoneNumber: "+14155550123" }).pipe(
            Effect.provideService(PhoneOtp.PhoneRequestContext, {
              networkKey: Redacted.make(networkKey),
            }),
            Effect.provideService(Auth.AuthRequest, {
              invocation: { _tag: "Guest" },
              credentials: {},
              credentialCommandSink: () => Effect.void,
            }),
            Effect.result,
          );

          expect(result).toMatchObject({ _tag: "Failure", failure: { _tag: "PhoneOtpRejected" } });
        }
      }).pipe(Effect.provide(AuthLive));

      expect(networks).toEqual(["network-a", "network-b"]);
    }),
);
