import {
  EmailProofDelivery,
  type ProofDeliveryMessage,
  type ProofDeliveryOutcome,
} from "@yielded/auth/Proofs";
import { Email } from "@yielded/auth/Schema";
import { Config, Effect, Layer, Redacted, Schema } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";

const SendResponse = Schema.Struct({
  success: Schema.Literal(true),
  result: Schema.Struct({
    delivered: Schema.Array(Schema.String),
    queued: Schema.Array(Schema.String),
    permanent_bounces: Schema.Array(Schema.String),
    suppressed_recipients: Schema.optionalKey(Schema.Array(Schema.String)),
  }),
});

// Cloudflare REST sending works with the local Bun server; no Worker binding is needed.
export const DeliveryLive = Layer.unwrap(
  Effect.gen(function* () {
    const accountId = yield* Config.string("CLOUDFLARE_ACCOUNT_ID");
    const token = yield* Config.redacted("CLOUDFLARE_API_TOKEN");

    const from = yield* Config.string("AUTH_EMAIL_FROM").pipe(
      Config.withDefault("hello@effect-agent.com"),
    );

    yield* Schema.decodeUnknownEffect(Schema.String.check(Schema.isPattern(/^[a-f0-9]{32}$/)))(
      accountId,
    );
    const sender = yield* Schema.decodeUnknownEffect(Email)(from);
    const client = yield* HttpClient.HttpClient;

    const send = Effect.fn("Customers.sendEmail")(function* (
      message: ProofDeliveryMessage,
    ): Effect.fn.Return<ProofDeliveryOutcome> {
      if (message.recipient.namespace !== "email" || message.format !== "numeric-code")
        return { _tag: "DefiniteFailure", reason: "policy" };

      const reset = message.purpose === "password-reset";
      const code = Redacted.value(message.secret);

      const result = yield* HttpClientRequest.post(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/email/sending/send`,
      ).pipe(
        HttpClientRequest.bearerToken(token),
        HttpClientRequest.acceptJson,
        HttpClientRequest.bodyJsonUnsafe({
          from: sender,
          to: message.recipient.value,
          subject: reset ? "Reset your password" : "Verify your email address",
          text: `${reset ? "Your password reset code" : "Your email verification code"} is ${code}.\n\nThis code expires in 5 minutes. If you did not request it, you can ignore this email.`,
        }),
        client.execute,
        Effect.flatMap((response) =>
          Effect.gen(function* () {
            if (response.status >= 400 && response.status < 500) {
              yield* Effect.logError("Cloudflare Email Sending rejected a message", {
                status: response.status,
              });

              return { _tag: "DefiniteFailure", reason: "unavailable" } as const;
            }
            if (response.status < 200 || response.status >= 300)
              return { _tag: "Ambiguous" } as const;
            const body = yield* HttpClientResponse.schemaBodyJson(SendResponse)(response);

            if (
              body.result.delivered.includes(message.recipient.value) ||
              body.result.queued.includes(message.recipient.value)
            )
              return { _tag: "Accepted" } as const;
            if (
              body.result.permanent_bounces.includes(message.recipient.value) ||
              body.result.suppressed_recipients?.includes(message.recipient.value)
            )
              return { _tag: "DefiniteFailure", reason: "recipient" } as const;

            return { _tag: "Ambiguous" } as const;
          }),
        ),
        Effect.timeout("8 seconds"),
        Effect.provideService(HttpClient.TracerDisabledWhen, () => true),
        Effect.orElseSucceed(() => ({ _tag: "Ambiguous" }) as const),
      );

      return result;
    });

    // Cloudflare does not promise delivery-ID deduplication. Never retry an uncertain send.
    return EmailProofDelivery.layer({ vendorId: "cloudflare", idempotencyMillis: 0 }, send);
  }),
);
