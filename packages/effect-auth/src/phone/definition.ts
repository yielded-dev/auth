import type {
  BindingOf,
  ClaimsCodec,
  StrategyBinding,
  StrategyDefinition,
  StrategyTypeLambda,
} from "../auth/definition";
import { snapshotPhoneConfiguration } from "./configuration";
import { makePhoneLifecycle } from "./lifecycle";
import { makePhoneOtp } from "./module";

export type PhoneOtpOptions<Namespace extends string | undefined = undefined> = Omit<
  Parameters<typeof makePhoneOtp>[1],
  "sessions"
> & { readonly namespace?: Namespace };

/** Bind the phone method to its Auth definition; runtime authorities come from Layers. */
const captureDefine = <const Namespace extends string | undefined>(
  _namespace: Namespace,
  input: PhoneOtpOptions<Namespace>,
) => {
  const options = snapshotPhoneConfiguration(input);

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

  return makePhoneOtp<Id, SessionId, Claims>(binding.namespace, {
    ...options,
    sessions: binding.sessions,
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
  input: PhoneOtpOptions<Namespace>,
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

/** Sign in existing phone credentials. Supply SMS delivery, storage, and account policy as Layers. */
export function make<const Namespace extends string>(
  options: PhoneOtpOptions<Namespace> & { readonly namespace: Namespace },
): ReturnType<typeof define<Namespace>>;

export function make<const Namespace extends string | undefined = undefined>(
  options: PhoneOtpOptions<Namespace>,
): ReturnType<typeof define<Namespace | undefined>>;

export function make<const Namespace extends string | undefined>(
  options: PhoneOtpOptions<Namespace>,
) {
  return define(options.namespace, options);
}

/** Opt into phone registration, verification, and number changes. Delivery remains a Layer. */
export type PhoneLifecycleOptions<Namespace extends string | undefined = undefined> = Omit<
  Parameters<typeof makePhoneLifecycle>[1],
  "sessions"
> & { readonly namespace?: Namespace };

/** Bind the phone method to its Auth definition; runtime authorities come from Layers. */
const captureLifecycle = <const Namespace extends string | undefined>(
  _namespace: Namespace,
  input: PhoneLifecycleOptions<Namespace>,
) => {
  const options = snapshotPhoneConfiguration({
    ...input,
    ...(input.lifecycle === undefined ? {} : { lifecycle: Object.freeze({ ...input.lifecycle }) }),
  });

  return { options };
};

const bindLifecycle = <
  const Namespace extends string | undefined,
  Claims extends ClaimsCodec,
  const Id extends string,
  const SessionId extends string,
>(
  binding: StrategyBinding<Claims, Id, SessionId>,
  captured: ReturnType<typeof captureLifecycle<Namespace>>,
) => {
  const { options } = captured;

  return makePhoneLifecycle<Id, SessionId, Claims>(binding.namespace, {
    ...options,
    sessions: binding.sessions,
  });
};

export interface LifecycleStrategy<
  Namespace extends string | undefined,
> extends StrategyTypeLambda {
  readonly type: ReturnType<
    typeof bindLifecycle<
      Namespace,
      BindingOf<this>["claims"],
      BindingOf<this>["namespace"],
      BindingOf<this>["sessionNamespace"]
    >
  >;
}

const defineLifecycle = <const Namespace extends string | undefined>(
  namespace: Namespace,
  input: PhoneLifecycleOptions<Namespace>,
) => {
  const captured = captureLifecycle<Namespace>(namespace, input);

  const bind = <
    Claims extends ClaimsCodec,
    const Id extends string,
    const SessionId extends string,
  >(
    binding: StrategyBinding<Claims, Id, SessionId>,
  ) => bindLifecycle<Namespace, Claims, Id, SessionId>(binding, captured);

  const definition: StrategyDefinition<LifecycleStrategy<Namespace>, Namespace> = {
    namespace,
    bind,
  };

  return Object.freeze(definition);
};

/**
 * Register, verify, or change phone numbers with independent action authorization.
 * Share the sign-in namespace to use the same credentials and claims service.
 */
export function makeLifecycle<const Namespace extends string>(
  options: PhoneLifecycleOptions<Namespace> & { readonly namespace: Namespace },
): ReturnType<typeof defineLifecycle<Namespace>>;

export function makeLifecycle<const Namespace extends string | undefined = undefined>(
  options: PhoneLifecycleOptions<Namespace>,
): ReturnType<typeof defineLifecycle<Namespace | undefined>>;

export function makeLifecycle<const Namespace extends string | undefined>(
  options: PhoneLifecycleOptions<Namespace>,
) {
  return defineLifecycle(options.namespace, options);
}
