import { Auth, Sessions } from "@yielded/auth";
import { Password, PhoneOtp } from "@yielded/auth/strategies";
import { Schema } from "effect";

export const Claims = Schema.Struct({ displayName: Schema.String });

export const AppAuth = Auth.make("customers", {
  claims: Claims,
  strategies: { password: Password.make(), phone: PhoneOtp.make() },
  sessions: Sessions.stateful(),
});

// The application decides which evidence is sufficient for its customers.
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
      userVerified: false,
      phishingResistant: false,
      minimumCredentials: 1,
    },
  ],
  maximumAgeMillis: 300_000,
});
