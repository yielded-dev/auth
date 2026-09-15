import { RequestBindingConfig } from "@yielded/auth/Auth";
import { PhoneDeliveryEligibility } from "@yielded/auth/PhoneOtp";
import { ProofKeys } from "@yielded/auth/Proofs";
import { SmsDelivery, type SmsMessage } from "@yielded/auth/SmsDelivery";
import { PhoneOtp } from "@yielded/auth/strategies";
import { Context, Effect, Encoding, Layer, Redacted, Ref } from "effect";

export class Inbox extends Context.Service<
  Inbox,
  {
    readonly messages: Effect.Effect<ReadonlyArray<SmsMessage>>;
  }
>()("example/Inbox") {}

const InboxLive = Layer.effectContext(
  Effect.gen(function* () {
    const messages = yield* Ref.make<ReadonlyArray<SmsMessage>>([]);

    return Context.make(Inbox, { messages: Ref.get(messages) }).pipe(
      Context.add(SmsDelivery, {
        send: (message) =>
          Ref.update(messages, (values) => [...values, message]).pipe(
            Effect.as({ _tag: "Accepted" as const }),
          ),
      }),
    );
  }),
);

// Public fixture keys, used only with this disposable database and local inbox.
const keys = {
  activeKeyId: "example",
  keys: [
    {
      id: "example",
      material: Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32).fill(91))),
    },
  ],
};

export const DeliveryLive = Layer.mergeAll(
  InboxLive,
  Layer.succeed(PhoneDeliveryEligibility, { allowed: () => Effect.succeed(true) }),
  PhoneOtp.Template.layer({ render: (code) => code }),
  ProofKeys.layer(keys),
  RequestBindingConfig.layer({ keyring: keys, lifetimeMillis: 120_000, generation: 1 }),
);
