import { Array, Layer } from "effect";

import { makeAuthStrategy } from "../auth/AuthStrategy";
import { cryptoLayer, defaultLayer, hooksLayer } from "../auth/defaults";
import type {
  BindingOf,
  ClaimsCodec,
  StrategyBinding,
  StrategyDefinition,
  StrategyTypeLambda,
} from "../auth/definition";
import type { OAuthAccountsPolicy } from "./accountsModels";
import type { OAuthConnectedPolicy } from "./connectedModels";
import type { OAuthRegistrationPolicy } from "./registrationModels";
import { defaultOAuthSignInPolicy, type OAuthSignInPolicy } from "./signInModels";
import { makeOAuthMethod } from "./signInModule";

export interface OAuthOptions<Namespace extends string | undefined = undefined> {
  readonly namespace?: Namespace;
  readonly policy?: Partial<OAuthSignInPolicy>;
}

export interface OAuthRegistrationOptions<
  Registration extends ClaimsCodec,
  Namespace extends string | undefined = undefined,
> extends OAuthOptions<Namespace> {
  readonly registration: Registration;
  readonly registrationPolicy: OAuthRegistrationPolicy;
}

const captureDefine = <const Namespace extends string | undefined>(
  _namespace: Namespace,
  input: OAuthOptions<Namespace>,
) => {
  const options = Object.freeze({
    ...input,
    policy: Object.freeze({ ...defaultOAuthSignInPolicy, ...input.policy }),
  });

  return { options };
};

const bindDefine = <
  const Namespace extends string | undefined,
  Claims extends ClaimsCodec,
  const Id extends string,
  const SessionId extends string,
>(
  binding: StrategyBinding<Claims, Id, SessionId>,
  captured: ReturnType<typeof captureDefine<Namespace>>,
) => {
  const { options } = captured;

  const module = makeOAuthMethod<Id, SessionId, Claims>(binding.namespace, {
    sessions: binding.sessions,
  });

  return Object.freeze({
    ...module,
    strategy: makeAuthStrategy(
      {
        signIn: module.signIn,
        completeSignIn: module.operations.Complete.invoke,
      },
      module.layer(options.policy).pipe(Layer.provideMerge(cryptoLayer)),
      { completion: true },
    ),
  });
};

export interface DefineStrategy<Namespace extends string | undefined> extends StrategyTypeLambda {
  readonly type: ReturnType<
    typeof bindDefine<
      Namespace,
      BindingOf<this>["claims"],
      BindingOf<this>["namespace"],
      BindingOf<this>["sessionNamespace"]
    >
  >;
}

const define = <const Namespace extends string | undefined>(
  namespace: Namespace,
  input: OAuthOptions<Namespace>,
) => {
  const captured = captureDefine<Namespace>(namespace, input);

  const bind = <
    Claims extends ClaimsCodec,
    const Id extends string,
    const SessionId extends string,
  >(
    binding: StrategyBinding<Claims, Id, SessionId>,
  ) => bindDefine<Namespace, Claims, Id, SessionId>(binding, captured);

  const definition: StrategyDefinition<DefineStrategy<Namespace>, Namespace> = {
    namespace,
    bind,
  };

  return Object.freeze(definition);
};

export function make<const Namespace extends string>(
  options: OAuthOptions<Namespace> & { readonly namespace: Namespace },
): ReturnType<typeof define<Namespace>>;

export function make<const Namespace extends string | undefined = undefined>(
  options?: OAuthOptions<Namespace>,
): ReturnType<typeof define<Namespace | undefined>>;

export function make<const Namespace extends string | undefined>(
  options: OAuthOptions<Namespace> = {},
) {
  return define(options.namespace, options);
}

const captureDefineRegistration = <
  Registration extends ClaimsCodec,
  const Namespace extends string | undefined = undefined,
>(
  _namespace: Namespace,
  input: OAuthRegistrationOptions<Registration, Namespace>,
) => {
  const options = Object.freeze({
    ...input,
    policy: Object.freeze({ ...defaultOAuthSignInPolicy, ...input.policy }),
    registrationPolicy: Object.freeze({ ...input.registrationPolicy }),
  });

  return { options };
};

const bindDefineRegistration = <
  Registration extends ClaimsCodec,
  const Namespace extends string | undefined,
  Claims extends ClaimsCodec,
  const Id extends string,
  const SessionId extends string,
>(
  binding: StrategyBinding<Claims, Id, SessionId>,
  captured: ReturnType<typeof captureDefineRegistration<Registration, Namespace>>,
) => {
  const { options } = captured;

  const module = makeOAuthMethod<Id, SessionId, Claims>(binding.namespace, {
    sessions: binding.sessions,
  });

  const registration = module.registration(options.registration);

  const layer = Layer.merge(module.handlersLayer, registration.handlersLayer).pipe(
    Layer.provide(
      Layer.merge(
        defaultLayer(
          module.SignIn,
          registration.signInLayer(options.policy, options.registrationPolicy),
        ),
        defaultLayer(registration.Registrations, registration.layer),
      ),
    ),
    Layer.provide(defaultLayer(module.binding.RequestBinding, module.binding.layer)),
    Layer.provide([cryptoLayer, hooksLayer]),
  );

  return Object.freeze({
    ...module,
    registration,
    strategy: makeAuthStrategy(
      {
        signIn: module.signIn,
        completeSignIn: module.operations.Complete.invoke,
        register: registration.operations.Complete.invoke,
      },
      layer.pipe(Layer.provideMerge(cryptoLayer)),
      { completion: true },
    ),
  });
};

export interface DefineRegistrationStrategy<
  Registration extends ClaimsCodec,
  Namespace extends string | undefined = undefined,
> extends StrategyTypeLambda {
  readonly type: ReturnType<
    typeof bindDefineRegistration<
      Registration,
      Namespace,
      BindingOf<this>["claims"],
      BindingOf<this>["namespace"],
      BindingOf<this>["sessionNamespace"]
    >
  >;
}

const defineRegistration = <
  Registration extends ClaimsCodec,
  const Namespace extends string | undefined = undefined,
>(
  namespace: Namespace,
  input: OAuthRegistrationOptions<Registration, Namespace>,
) => {
  const captured = captureDefineRegistration<Registration, Namespace>(namespace, input);

  const bind = <
    Claims extends ClaimsCodec,
    const Id extends string,
    const SessionId extends string,
  >(
    binding: StrategyBinding<Claims, Id, SessionId>,
  ) => bindDefineRegistration<Registration, Namespace, Claims, Id, SessionId>(binding, captured);

  const definition: StrategyDefinition<
    DefineRegistrationStrategy<Registration, Namespace>,
    Namespace
  > = {
    namespace,
    bind,
  };

  return Object.freeze(definition);
};

export function makeRegistration<Registration extends ClaimsCodec, const Namespace extends string>(
  options: OAuthRegistrationOptions<Registration, Namespace> & { readonly namespace: Namespace },
): ReturnType<typeof defineRegistration<Registration, Namespace>>;

export function makeRegistration<
  Registration extends ClaimsCodec,
  const Namespace extends string | undefined = undefined,
>(
  options: OAuthRegistrationOptions<Registration, Namespace>,
): ReturnType<typeof defineRegistration<Registration, Namespace | undefined>>;

/** Registration selects the protocol's registration transition and its separate completion. */
export function makeRegistration<
  Registration extends ClaimsCodec,
  const Namespace extends string | undefined,
>(options: OAuthRegistrationOptions<Registration, Namespace>) {
  return defineRegistration(options.namespace, options);
}

export interface OAuthAccountsOptions<Namespace extends string | undefined = undefined> {
  readonly namespace?: Namespace;
  readonly policy: OAuthAccountsPolicy;
}

const captureDefineAccounts = <const Namespace extends string | undefined>(
  _namespace: Namespace,
  input: OAuthAccountsOptions<Namespace>,
) => {
  const options = Object.freeze({ ...input, policy: Object.freeze({ ...input.policy }) });

  return { options };
};

const bindDefineAccounts = <
  const Namespace extends string | undefined,
  Claims extends ClaimsCodec,
  const Id extends string,
  const SessionId extends string,
>(
  binding: StrategyBinding<Claims, Id, SessionId>,
  captured: ReturnType<typeof captureDefineAccounts<Namespace>>,
) => {
  const { options } = captured;

  return makeOAuthMethod<Id, SessionId, Claims>(binding.namespace, {
    sessions: binding.sessions,
  }).accounts(options.policy);
};

export interface DefineAccountsStrategy<
  Namespace extends string | undefined,
> extends StrategyTypeLambda {
  readonly type: ReturnType<
    typeof bindDefineAccounts<
      Namespace,
      BindingOf<this>["claims"],
      BindingOf<this>["namespace"],
      BindingOf<this>["sessionNamespace"]
    >
  >;
}

const defineAccounts = <const Namespace extends string | undefined>(
  namespace: Namespace,
  input: OAuthAccountsOptions<Namespace>,
) => {
  const captured = captureDefineAccounts<Namespace>(namespace, input);

  const bind = <
    Claims extends ClaimsCodec,
    const Id extends string,
    const SessionId extends string,
  >(
    binding: StrategyBinding<Claims, Id, SessionId>,
  ) => bindDefineAccounts<Namespace, Claims, Id, SessionId>(binding, captured);

  const definition: StrategyDefinition<DefineAccountsStrategy<Namespace>, Namespace> = {
    namespace,
    bind,
  };

  return Object.freeze(definition);
};

export function makeAccounts<const Namespace extends string>(
  options: OAuthAccountsOptions<Namespace> & { readonly namespace: Namespace },
): ReturnType<typeof defineAccounts<Namespace>>;

export function makeAccounts<const Namespace extends string | undefined = undefined>(
  options: OAuthAccountsOptions<Namespace>,
): ReturnType<typeof defineAccounts<Namespace | undefined>>;

export function makeAccounts<const Namespace extends string | undefined>(
  options: OAuthAccountsOptions<Namespace>,
) {
  return defineAccounts(options.namespace, options);
}

export interface OAuthConnectedOptions<Namespace extends string | undefined = undefined> {
  readonly namespace?: Namespace;
  readonly policy: OAuthConnectedPolicy;
}

const captureDefineConnected = <const Namespace extends string | undefined>(
  _namespace: Namespace,
  input: OAuthConnectedOptions<Namespace>,
) => {
  const options = Object.freeze({
    ...input,
    policy: Object.freeze({
      ...input.policy,
      profiles: globalThis.Array.isArray(input.policy?.profiles)
        ? Object.freeze(
            Array.map(input.policy?.profiles, (profile) =>
              Object.freeze({
                ...profile,
                scopes: globalThis.Array.isArray(profile?.scopes)
                  ? Object.freeze([...profile.scopes])
                  : profile?.scopes,
                resources: globalThis.Array.isArray(profile?.resources)
                  ? Object.freeze([...profile.resources])
                  : profile?.resources,
              }),
            ),
          )
        : input.policy?.profiles,
    }),
  });

  return { options };
};

const bindDefineConnected = <
  const Namespace extends string | undefined,
  Claims extends ClaimsCodec,
  const Id extends string,
  const SessionId extends string,
>(
  binding: StrategyBinding<Claims, Id, SessionId>,
  captured: ReturnType<typeof captureDefineConnected<Namespace>>,
) => {
  const { options } = captured;

  return makeOAuthMethod<Id, SessionId, Claims>(binding.namespace, {
    sessions: binding.sessions,
  }).connected(options.policy);
};

export interface DefineConnectedStrategy<
  Namespace extends string | undefined,
> extends StrategyTypeLambda {
  readonly type: ReturnType<
    typeof bindDefineConnected<
      Namespace,
      BindingOf<this>["claims"],
      BindingOf<this>["namespace"],
      BindingOf<this>["sessionNamespace"]
    >
  >;
}

const defineConnected = <const Namespace extends string | undefined>(
  namespace: Namespace,
  input: OAuthConnectedOptions<Namespace>,
) => {
  const captured = captureDefineConnected<Namespace>(namespace, input);

  const bind = <
    Claims extends ClaimsCodec,
    const Id extends string,
    const SessionId extends string,
  >(
    binding: StrategyBinding<Claims, Id, SessionId>,
  ) => bindDefineConnected<Namespace, Claims, Id, SessionId>(binding, captured);

  const definition: StrategyDefinition<DefineConnectedStrategy<Namespace>, Namespace> = {
    namespace,
    bind,
  };

  return Object.freeze(definition);
};

export function makeConnected<const Namespace extends string>(
  options: OAuthConnectedOptions<Namespace> & { readonly namespace: Namespace },
): ReturnType<typeof defineConnected<Namespace>>;

export function makeConnected<const Namespace extends string | undefined = undefined>(
  options: OAuthConnectedOptions<Namespace>,
): ReturnType<typeof defineConnected<Namespace | undefined>>;

export function makeConnected<const Namespace extends string | undefined>(
  options: OAuthConnectedOptions<Namespace>,
) {
  return defineConnected(options.namespace, options);
}
