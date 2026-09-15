import { Auth, Sessions } from "@yielded/auth";
import { Email, Passkey, Password } from "@yielded/auth/strategies";

import { AuthApi, emailProofPolicy, Registration } from "./contract";

export const sessionConfiguration = Sessions.stateful();

const sessionLifetimeMillis = sessionConfiguration.policy(
  AuthApi.sessions.moduleId,
).absoluteLifetimeMillis;

export const AppAuth = Auth.make(AuthApi, {
  strategies: {
    password: Password.make({
      registration: Registration,
      reset: { secret: { _tag: "NumericCode", digits: 6 }, policy: emailProofPolicy },
    }),
    email: Email.makeAddresses({
      policy: emailProofPolicy,
      addresses: { maximumEvidenceAgeMillis: 300_000, requireImmediateInvalidation: true },
    }),
    passkey: Passkey.make(),
    passkeys: Passkey.makeManagement({
      policy: { generation: 2 },
      management: {
        maximumCredentials: 5,
        maximumEvidenceAgeMillis: sessionLifetimeMillis,
        requireImmediateInvalidation: true,
      },
    }),
  },
  sessions: sessionConfiguration,
});

export const recoveryRequirement = Sessions.AuthenticationRequirement.make({
  alternatives: [
    {
      factors: ["possession"],
      userVerified: false,
      phishingResistant: false,
      minimumCredentials: 1,
    },
  ],
  maximumAgeMillis: 60_000,
});

// A password or a user-verified passkey can sign in. Verified email permits recovery.
export const requirement = Sessions.AuthenticationRequirement.make({
  alternatives: [
    {
      factors: ["knowledge"],
      userVerified: false,
      phishingResistant: false,
      minimumCredentials: 1,
    },
    {
      factors: ["possession"],
      userVerified: true,
      phishingResistant: true,
      minimumCredentials: 1,
    },
  ],
  maximumAgeMillis: 300_000,
});

// Email confirmation and adding a passkey accept the existing valid session.
export const sessionRequirement = Sessions.AuthenticationRequirement.make({
  ...requirement,
  maximumAgeMillis: sessionLifetimeMillis,
});
