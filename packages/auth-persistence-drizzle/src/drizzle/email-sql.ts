import {
  makeEmailAddressWorkflow,
  type AnyEmailAddressMapping,
  type AnyEmailSignInMapping,
} from "@yielded/auth-persistence/Adapter";
import { EmailSignInTargets } from "@yielded/auth/Email";
import { Effect, Option } from "effect";

import { CurrentEmailSql, type EmailSqlConfiguration } from "./email-database";
import * as N from "./email-native";
import { makeEmailOwner } from "./email-store";
import { NativeDatabase } from "./native-database";
import { validateDrizzleStorage } from "./storage-validation";

export { CurrentEmailSql } from "./email-database";
export type { EmailSqlConfiguration, CurrentAddress } from "./email-database";

export {
  validEmailSignInConstraints,
  emailLookupQuery,
  decodeEmailSnapshot,
  currentAddress,
  validateEmailAuthority,
} from "./email-native";

export const makeSqlEmailSignInTargets = Effect.fnUntraced(function* (
  mapping: AnyEmailSignInMapping,
  configuration: EmailSqlConfiguration,
) {
  const database = yield* CurrentEmailSql;

  if (!N.validEmailSignInConstraints(mapping)) return yield* N.unavailable();
  if (!configuration.coordinated)
    yield* validateDrizzleStorage({ ...mapping, proof: configuration.proof?.mapping }).pipe(
      Effect.mapError(N.unavailable),
    );

  return EmailSignInTargets.of({
    lookup: (input) =>
      N.safeRead(
        database,
        configuration,
        Effect.gen(function* () {
          const row = (yield* N.emailLookupRows(mapping, input.moduleId, input.identifier))[0];

          const snapshot =
            row === undefined
              ? undefined
              : yield* N.decodeEmailSnapshot(mapping, input.moduleId, input.identifier, row);

          return snapshot === undefined ? Option.none() : Option.some(snapshot);
        }),
      ).pipe(Effect.provideService(CurrentEmailSql, database), N.translateFailure),
  });
});

export const makeSqlEmailAddressPersistence = Effect.fnUntraced(function* (
  mapping: AnyEmailAddressMapping,
  configured: EmailSqlConfiguration,
) {
  const database = yield* CurrentEmailSql;
  const native = yield* NativeDatabase;
  const maxParameters = configured.maxParameters ?? native.maxParameters ?? 96;

  const configuration: EmailSqlConfiguration = {
    ...configured,
    maxParameters,
    pgOrderedLocks: native.$client.onDialectOrElse({
      pg: () => configured.locking,
      orElse: () => false,
    }),
    ...(configured.proof === undefined
      ? {}
      : {
          proof: {
            ...configured.proof,
            configuration: {
              ...configured.proof.configuration,
              maxParameters: configured.proof.configuration.maxParameters ?? maxParameters,
              pgOrderedLocks: native.$client.onDialectOrElse({
                pg: () => configured.proof!.configuration.locking,
                orElse: () => false,
              }),
            },
          },
        }),
  };

  if (!N.validAddressConstraints(mapping)) return yield* N.unavailable();
  if (!configuration.coordinated)
    yield* validateDrizzleStorage({ ...mapping, proof: configuration.proof?.mapping }).pipe(
      Effect.mapError(N.unavailable),
    );
  const owner = makeEmailOwner(mapping, configuration, database);
  const { proof, ...options } = configuration;

  return yield* makeEmailAddressWorkflow(
    mapping,
    { ...options, ...(proof === undefined ? {} : { proof: proof.mapping }) },
    owner,
  );
});
