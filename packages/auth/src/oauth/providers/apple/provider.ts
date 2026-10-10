import type { Hmac } from "@yielded/crypto/Hmac";
import type { Signature } from "@yielded/crypto/Signature";
import { Jwk, Jwt } from "@yielded/jose";
import { Unavailable } from "@yielded/oauth/Errors";
import { Clock, Effect, Redacted, Result, Schema } from "effect";
import { Base64 } from "effect/encoding";

import type { ProviderDefinition } from "../../providerDefinition";
import { type OAuthUnavailable } from "../../signInErrors";
import { discoveryProfile } from "../shared/discovery";
import { provider as oidcProvider } from "../shared/layer";
import { OpenIdConnectConfigurationError } from "../shared/models";
import type { Requirements } from "../shared/oidc";
import { resolveOptions } from "../shared/options";
import { AppleUserProfile } from "./profile";

const identifier = Schema.NonEmptyString.check(Schema.isPattern(/^[A-Z0-9]{10}$/));

const pem = Schema.toType(
  Schema.RedactedFromValue(Schema.NonEmptyString.check(Schema.isMaxLength(16384))),
);

const lifetime = Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 15_777_000 }));

const Registration = Schema.Struct({
  clientId: Schema.NonEmptyString,
  teamId: identifier,
  keyId: identifier,
  privateKey: pem,
  configurationGeneration: Schema.optionalKey(Schema.Int),
  issuance: Schema.optionalKey(Schema.Literals(["active", "retired"])),
  scopes: Schema.optionalKey(Schema.Array(Schema.Literals(["openid", "email", "name"]))),
  clientSecretLifetimeSeconds: Schema.optionalKey(lifetime),
});

export type ProviderRegistration = typeof Registration.Type;

export type ProviderOptions = {
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
} & (ProviderRegistration | { readonly registrations: ReadonlyArray<ProviderRegistration> });

const ClientSecret = Schema.Struct({
  iss: Schema.NonEmptyString,
  sub: Schema.NonEmptyString,
  aud: Schema.Literal("https://appleid.apple.com"),
  iat: Schema.Finite,
  exp: Schema.Finite,
});

const decodePem = (value: string): Uint8Array | undefined =>
  Result.getOrUndefined(
    Base64.decode(
      value
        .replace(/\\r\\n|\\n/g, "\n")
        .replace(/-----[A-Z ]+-----/g, "")
        .replace(/\s/g, ""),
    ),
  );

const importSigningKey = Effect.fnUntraced(function* (
  privateKey: ProviderRegistration["privateKey"],
  keyId: string,
) {
  const der = decodePem(Redacted.value(privateKey));

  if (der === undefined || der.length === 0)
    return yield* OpenIdConnectConfigurationError.make({ reason: "authentication" });

  return yield* Jwk.importPkcs8(Redacted.make(der), "ES256", { kid: keyId }).pipe(
    Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "authentication" })),
  );
});

/** Mint the ES256 client-secret JWT Apple requires at the token endpoint.
 * Lifetime defaults to 5 minutes and cannot exceed 6 months (15,777,000 seconds). */
export const mintClientSecret = Effect.fn("Apple.mintClientSecret")(function* (options: {
  readonly teamId: string;
  readonly clientId: string;
  readonly keyId: string;
  readonly privateKey: ProviderRegistration["privateKey"];
  readonly lifetimeSeconds?: number;
}) {
  const teamId = yield* Schema.decodeEffect(identifier)(options.teamId).pipe(
    Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "provider" })),
  );

  const keyId = yield* Schema.decodeEffect(identifier)(options.keyId).pipe(
    Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "provider" })),
  );

  const lifetimeSeconds = yield* Schema.decodeEffect(lifetime)(
    options.lifetimeSeconds === undefined ? 300 : options.lifetimeSeconds,
  ).pipe(Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "provider" })));

  const key = yield* importSigningKey(options.privateKey, keyId);
  const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

  return yield* Jwt.sign(
    ClientSecret,
    {
      iss: teamId,
      sub: options.clientId,
      aud: "https://appleid.apple.com",
      iat: now,
      exp: now + lifetimeSeconds,
    },
    key,
    { alg: "ES256", kid: keyId },
  ).pipe(Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "authentication" })));
});

/** Sign in with Apple through the shared OIDC implementation. Defaults to the
 * openid scope, client_secret_post, form_post callbacks, advertised RS256, and
 * no PKCE. AppleUserProfile decodes string email_verified / is_private_email
 * flags. Name arrives once in the user form field on first consent and is merged
 * into that profile. No UserInfo request or retained API access is installed.
 * Credentials are captured when the host builds its Layer; supply HttpClient and
 * crypto in that Scope. */
export const provider = (
  options: ProviderOptions,
): ProviderDefinition<OpenIdConnectConfigurationError | OAuthUnavailable, Requirements> => ({
  configure: (binding) =>
    resolveOptions(() =>
      Effect.gen(function* () {
        const registrations = yield* Schema.decodeEffect(Schema.Array(Registration))(
          "registrations" in options ? options.registrations : [options],
        ).pipe(Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "provider" })));

        const services = yield* Effect.context<Hmac | Signature>();

        const prepared = yield* Effect.forEach(registrations, (registration) =>
          Effect.gen(function* () {
            const key = yield* importSigningKey(registration.privateKey, registration.keyId);

            const lifetimeSeconds =
              registration.clientSecretLifetimeSeconds === undefined
                ? 300
                : registration.clientSecretLifetimeSeconds;

            Redacted.wipeUnsafe(registration.privateKey);
            yield* Effect.addFinalizer(() => Effect.sync(() => Redacted.wipeUnsafe(key.material)));

            const {
              privateKey: _privateKey,
              clientSecretLifetimeSeconds: _lifetime,
              teamId: _teamId,
              keyId: _keyId,
              ...rest
            } = registration;

            return {
              ...rest,
              protocol: "oidc" as const,
              issuer: "https://appleid.apple.com",
              responseIssuerMode: "unsupported" as const,
              responseMode: "form_post" as const,
              pkceS256: false,
              idTokenSignedResponseAlg: "RS256" as const,
              profileSchema: AppleUserProfile,
              [discoveryProfile]: "apple" as const,
              authentication: {
                method: "client_secret_post" as const,
                mintSecret: () =>
                  Effect.gen(function* () {
                    const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

                    return yield* Jwt.sign(
                      ClientSecret,
                      {
                        iss: registration.teamId,
                        sub: registration.clientId,
                        aud: "https://appleid.apple.com",
                        iat: now,
                        exp: now + lifetimeSeconds,
                      },
                      key,
                      { alg: "ES256", kid: registration.keyId },
                    ).pipe(Effect.mapError(() => Unavailable.make({})));
                  }).pipe(Effect.provideContext(services)),
              },
            };
          }),
        );

        return yield* oidcProvider({
          registrations: prepared,
          ...(options.timeoutSeconds === undefined
            ? {}
            : { timeoutSeconds: options.timeoutSeconds }),
        }).configure(binding);
      }),
    ),
});
