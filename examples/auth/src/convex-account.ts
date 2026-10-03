import { Auth, Password, Sessions } from "@yielded/auth";
import * as Convex from "@yielded/auth-persistence-convex";
import { Schema } from "effect";

export const Claims = Schema.Struct({ displayName: Schema.String });

export const accounts = Auth.make("convex/accounts", {
  claims: Claims,
  sessions: Sessions.stateful(),
  defaultStrategy: "password",
  strategies: {
    password: Password.make({ registration: Claims, reset: { secret: { _tag: "Token" } } }),
  },
});

export const requirement = Sessions.AuthenticationRequirement.make({
  alternatives: [
    {
      factors: ["knowledge"],
      minimumCredentials: 1,
      userVerified: false,
      phishingResistant: false,
    },
  ],
  maximumAgeMillis: 300_000,
});

export const recoveryRequirement = Sessions.AuthenticationRequirement.make({
  ...requirement,
  alternatives: [
    {
      factors: ["possession"],
      minimumCredentials: 1,
      userVerified: false,
      phishingResistant: false,
    },
  ],
});

export const persistence = Convex.managed(accounts, {
  requirements: {
    signIn: requirement,
    actions: {
      ...requirement,
      alternatives: [...requirement.alternatives, ...recoveryRequirement.alternatives],
    },
  },
});
