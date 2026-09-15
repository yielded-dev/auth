import { Console, Context, DateTime, type Effect, Layer, Redacted } from "effect";

import type { EmailDeliveryError } from "./Errors";
import type { EmailOtpMessage } from "./Schema";

/**
 * OTP-specific delivery port, not a generic mail client. The consumer owns
 * provider calls and message templating.
 */
export class EmailOtpSender extends Context.Service<
  EmailOtpSender,
  {
    readonly send: (message: EmailOtpMessage) => Effect.Effect<void, EmailDeliveryError>;
  }
>()("effect-auth/EmailOtpSender") {
  /**
   * Reveals the code through Effect's `Console` for local development. This is
   * the sole deliberate exception to the no-secrets-in-logs rule and is
   * explicitly not a production layer.
   */
  static readonly layerConsole = Layer.succeed(EmailOtpSender)({
    send: (message) =>
      Console.log(
        `[effect-auth] sign-in code for ${message.email}: ${Redacted.value(message.code)}` +
          ` (expires ${DateTime.formatIso(message.expiresAt)})`,
      ),
  });
}
