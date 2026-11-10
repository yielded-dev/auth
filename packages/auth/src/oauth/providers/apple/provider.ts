import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Base64 from "effect/encoding/Base64";
import * as Jwk from "effect/jose/Jwk";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";

import type { ProviderDefinition } from "../../providerDefinition";
import { type OAuthUnavailable } from "../../signInErrors";
import { nativeAudiences } from "../shared/compatibility";
import { discoveryProfile } from "../shared/discovery";
import { provider as oidcProvider } from "../shared/layer";
import { OpenIdConnectConfigurationError } from "../shared/models";
import type { Requirements } from "../shared/oidc";
import { resolveOptions } from "../shared/options";
import { signPrivateKeyJwt } from "../shared/privateKeyJwt";
import { AppleUserProfile } from "./profile";

const identifier = Schema.NonEmptyString.check(Schema.isPattern(/^[A-Z0-9]{10}$/));

const pem = Schema.toType(
  Schema.RedactedFromValue(Schema.NonEmptyString.check(Schema.isMaxLength(16384))),
);

const lifetime = Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 15_777_000 }));

const generation = {
  configurationGeneration: Schema.optionalKey(Schema.Int),
  issuance: Schema.optionalKey(Schema.Literals(["active", "retired"])),
};

/** Browser sign-in with a Services ID and the key that signs Apple client secrets. */
const WebRegistration = Schema.Struct({
  kind: Schema.optionalKey(Schema.Literal("web")),
  clientId: Schema.NonEmptyString,
  teamId: identifier,
  keyId: identifier,
  privateKey: pem,
  ...generation,
  scopes: Schema.optionalKey(Schema.Array(Schema.Literals(["openid", "email", "name"]))),
  clientSecretLifetimeSeconds: Schema.optionalKey(lifetime),
});

/** Native sign-in from `ASAuthorizationController` in the listed apps, such as an iOS
 * and a macOS app. Each bundle ID is an accepted ID-token audience. Apple's `sub` is
 * team-scoped, so list only apps from the team that owns the web Services ID. */
const NativeRegistration = Schema.Struct({
  kind: Schema.Literal("native"),
  bundleIds: Schema.NonEmptyArray(Schema.NonEmptyString.check(Schema.isMaxLength(1024))).check(
    Schema.isMaxLength(64),
  ),
  ...generation,
});

const Registration = Schema.Union([NativeRegistration, WebRegistration]);

export type WebRegistration = typeof WebRegistration.Type;
export type NativeRegistration = typeof NativeRegistration.Type;
export type ProviderRegistration = typeof Registration.Type;

export type ProviderOptions = {
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
} & (ProviderRegistration | { readonly registrations: ReadonlyArray<ProviderRegistration> });

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
  privateKey: WebRegistration["privateKey"],
  keyId: string,
) {
  const der = decodePem(Redacted.value(privateKey));

  if (der === undefined || der.length === 0)
    return yield* OpenIdConnectConfigurationError.make({ reason: "authentication" });

  return yield* Jwk.importPkcs8(Redacted.make(der), "ES256", { kid: keyId }).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(
        Cause.map(cause, () => OpenIdConnectConfigurationError.make({ reason: "authentication" })),
      ),
    ),
  );
});

/** Mint the ES256 client-secret JWT Apple requires at the token endpoint.
 * Lifetime defaults to 5 minutes and cannot exceed 6 months (15,777,000 seconds). */
export const mintClientSecret = Effect.fn("Apple.mintClientSecret")(function* (options: {
  readonly teamId: string;
  readonly clientId: string;
  readonly keyId: string;
  readonly privateKey: WebRegistration["privateKey"];
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

  return yield* signPrivateKeyJwt(
    {
      algorithm: "ES256",
      keyId,
      issuer: teamId,
      subject: options.clientId,
      audience: "https://appleid.apple.com",
      lifetimeSeconds,
    },
    key,
  ).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(
        Cause.map(cause, () => OpenIdConnectConfigurationError.make({ reason: "authentication" })),
      ),
    ),
  );
});

/** Sign in with Apple through the shared OIDC implementation. Defaults to the
 * openid scope, client_secret_post, form_post callbacks, advertised RS256, and
 * no PKCE. AppleUserProfile decodes boolean or string email_verified /
 * is_private_email flags. Name arrives once on first consent and is merged
 * into that profile. A `kind: "native"` registration adds native sign-in for its
 * bundle IDs, with or without a web Services ID registration; it needs no key.
 * No UserInfo request or retained API access is installed.
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

        const apple = {
          protocol: "oidc" as const,
          issuer: "https://appleid.apple.com",
          responseIssuerMode: "unsupported" as const,
          responseMode: "form_post" as const,
          pkceS256: false,
          idTokenSignedResponseAlg: "RS256" as const,
          profileSchema: AppleUserProfile,
          [discoveryProfile]: "apple" as const,
        };

        const prepared = yield* Effect.forEach(registrations, (registration) =>
          Effect.gen(function* () {
            if (registration.kind === "native") {
              const { kind: _kind, bundleIds, ...rest } = registration;

              // A public app client: no secret and no token client.
              return {
                ...rest,
                ...apple,
                clientId: bundleIds[0],
                [nativeAudiences]: bundleIds,
                authentication: { method: "none" as const, publicClient: true as const },
              };
            }
            const der = decodePem(Redacted.value(registration.privateKey));

            if (der === undefined || der.length === 0)
              return yield* OpenIdConnectConfigurationError.make({ reason: "authentication" });

            const encoded = Base64.encode(der);

            yield* importSigningKey(registration.privateKey, registration.keyId).pipe(
              Effect.ensuring(
                Effect.sync(() => {
                  der.fill(0);
                  Redacted.wipeUnsafe(registration.privateKey);
                }),
              ),
            );

            const lifetimeSeconds =
              registration.clientSecretLifetimeSeconds === undefined
                ? 300
                : registration.clientSecretLifetimeSeconds;

            const {
              kind: _kind,
              privateKey: _privateKey,
              clientSecretLifetimeSeconds: _lifetime,
              teamId,
              keyId,
              ...rest
            } = registration;

            return {
              ...rest,
              ...apple,
              authentication: {
                method: "client_secret_post" as const,
                privateKeyJwt: {
                  algorithm: "ES256" as const,
                  keyId,
                  issuer: teamId,
                  subject: registration.clientId,
                  audience: "https://appleid.apple.com",
                  lifetimeSeconds,
                  privateKey: Redacted.make(encoded),
                },
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
