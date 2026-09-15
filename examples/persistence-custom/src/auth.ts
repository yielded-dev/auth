import { Auth } from "@yielded/auth";
import { Password } from "@yielded/auth/strategies";

import { accountStrategies, sessionConfiguration } from "../../shared/account/auth";
import { emailProofPolicy } from "../../shared/account/contract";
import { AuthApi, Registration } from "./contract";
import { AccountStrategy } from "./methods";

export const AppAuth = Auth.make(AuthApi, {
  strategies: {
    ...accountStrategies,
    account: AccountStrategy,
    password: Password.make({
      registration: Registration,
      reset: { secret: { _tag: "NumericCode", digits: 6 }, policy: emailProofPolicy },
    }),
  },
  sessions: sessionConfiguration,
});
