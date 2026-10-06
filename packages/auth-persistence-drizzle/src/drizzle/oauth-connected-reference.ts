import type { SQL, Table } from "drizzle-orm";

import type { OAuthConnectedMapping } from "./oauth-connected-model";
import { oauthKernel } from "./oauth-kernel";
import type { OAuthReferenceGuardDescriptor } from "./oauth-model";

/** Compose login unlink with retained-grant ownership under this compiler. */
export const oauthConnectedOwnershipReferences = <
  S extends Table,
  AC extends Table,
  T extends Table,
  O extends Table,
  F extends Table,
  G extends Table,
  C extends Table,
  H extends Table,
  A extends Table,
  D extends Table,
  N,
  J extends Table,
>(
  original: OAuthConnectedMapping<S, AC, T, O, F, G, C, H, A, D, N, J>,
): {
  readonly connectedReferenceGuards: ReadonlyArray<OAuthReferenceGuardDescriptor<N>>;
  readonly connectedReference: (input: {
    readonly identityKey: string;
    readonly subjectId: N;
  }) => SQL;
} =>
  // The shared kernel returns this adapter's expressions; only compiler handles are erased.
  oauthKernel.connectedReference.oauthConnectedOwnershipReferences(original) as {
    readonly connectedReferenceGuards: ReadonlyArray<OAuthReferenceGuardDescriptor<N>>;
    readonly connectedReference: (input: {
      readonly identityKey: string;
      readonly subjectId: N;
    }) => SQL;
  };
