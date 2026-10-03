import { Context, type Redacted } from "effect";

/** Host-verified opaque ingress identity, supplied per invocation. Never accept
 * these keys in operation payloads or install a caller in a shared auth Layer.
 */
export class ProofRequestContext extends Context.Service<
  ProofRequestContext,
  {
    readonly networkKey: Redacted.Redacted<string>;
    readonly deviceKey?: Redacted.Redacted<string>;
  }
>()("effect-auth/ProofRequestContext") {}
