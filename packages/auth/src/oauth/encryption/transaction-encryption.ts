import { Effect, Redacted, type Schema } from "effect";

import { OAuthUnavailable } from "../signInErrors";
import { OAuthSealedTransaction, type OAuthTransactionSecrets } from "../signInModels";
import type { OAuthTransactionKeyring } from "../transactionKeyring";
import { decodeBase64, payloadEncryption } from "./payload";

export const transactionEncryption = <
  C extends { readonly protocol: "oidc" | "oauth" },
  S extends OAuthTransactionSecrets,
>(
  context: Schema.Codec<C, unknown, never, never>,
  aad: (context: C, keyId: string) => Uint8Array,
  keyring: OAuthTransactionKeyring,
  plaintext: Schema.Codec<S, unknown, never, never>,
  envelope: {
    readonly schema: Schema.Codec<OAuthSealedTransaction, unknown, never, never>;
    readonly maximumPlaintextBytes: number;
  } = { schema: OAuthSealedTransaction, maximumPlaintextBytes: 16384 },
) =>
  payloadEncryption(
    {
      context,
      aad,
      plaintext,
      envelope: envelope.schema,
      format: "oauth-xchacha20poly1305-v1",
      maximumPlaintextBytes: envelope.maximumPlaintextBytes,
      validate: (context, secrets) => {
        if ((context.protocol === "oidc") !== (secrets.oidcNonce !== undefined))
          throw OAuthUnavailable.make({});
        for (const raw of [secrets.state, secrets.oidcNonce])
          if (raw !== undefined) decodeBase64(Redacted.value(raw), 32, 32).fill(0);

        return secrets;
      },
    },
    keyring,
  ).pipe(
    Effect.map((encryption) => ({
      seal: (input: { readonly context: C; readonly secrets: S }) =>
        encryption.seal(input.context, input.secrets),
      open: (input: { readonly context: C; readonly sealed: OAuthSealedTransaction }) =>
        encryption.open(input.context, input.sealed),
    })),
  );
