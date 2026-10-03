import type { LoginIdentifier } from "@yielded/auth/Identity";
import * as Password from "@yielded/auth/Password";
import * as Proofs from "@yielded/auth/Proofs";
import { SubjectId } from "@yielded/auth/Schema";
import * as Sessions from "@yielded/auth/Sessions";
import type { Context } from "effect";
import { Effect, Layer, Option, Schema } from "effect";

import { DocumentFunctions, DocumentStore, Transaction, type Codec } from "./documents";
import { identityPartitions, Subject } from "./identity";
import {
  makePasswordRegistration,
  PasswordPersistence,
  type PasswordProvisioning,
  type ProvisioningService,
  type RegistrationService,
} from "./passwords";
import { ActionContext } from "./persistence";
import { ProofPersistence } from "./proofs";
import { makeSessions, type SessionDefinition } from "./sessions";

export interface ManagedOptions {
  readonly requirements: {
    readonly signIn: Sessions.AuthenticationRequirement;
    /** Defaults to signIn. This does not supply the application's action-evidence verifier. */
    readonly actions?: Sessions.AuthenticationRequirement;
  };
}

export interface ManagedPassword<Data, Claims, RegistrationId, ClaimsId> {
  readonly persistence: {
    readonly kind: "password";
    readonly moduleId: string;
    readonly management: true;
  };
  readonly RegistrationAuthority: Context.Key<RegistrationId, RegistrationService<Data>>;
  readonly SessionClaims: Context.Key<
    ClaimsId,
    {
      readonly resolve: (input: {
        readonly subjectId: SubjectId;
        readonly credential: Password.PasswordCredentialSnapshot;
      }) => Effect.Effect<Claims, Password.PasswordUnavailable>;
    }
  >;
}

type ProvisioningKey<Strategy> =
  Strategy extends ManagedPassword<infer Data, infer _Claims, infer RegistrationId, infer _ClaimsId>
    ? Context.Service<PasswordProvisioning<RegistrationId, Data>, ProvisioningService<Data>>
    : never;

/** Explicitly supplied services take precedence over the provider's defaults. */
const defaultLayer = <I, S, E, R>(
  key: Context.Key<I, S>,
  fallback: Layer.Layer<I, E, R>,
): Layer.Layer<I, E, R> =>
  Layer.unwrap(
    Effect.map(Effect.serviceOption(key), (current) =>
      Option.isSome(current) ? Layer.succeed(key, current.value) : fallback,
    ),
  );

/** Managed password accounts store registration values as claims after Schema validation.
 * Applications own policy and can supply any of the existing persistence or account services.
 * Each layer invocation belongs to its Convex action; callbacks still prepare before commit.
 */
export const managed = <
  C extends Codec,
  Data,
  RegistrationId,
  ClaimsId,
  Stateful,
  Repository,
  Pending,
  Signed,
  const Strategies extends Readonly<
    Record<string, ManagedPassword<Data, C["Type"], RegistrationId, ClaimsId>>
  >,
>(
  auth: {
    readonly namespace: string;
    readonly claims: C;
    readonly sessions: SessionDefinition<C["Type"], Stateful, Repository, Pending, Signed>;
    readonly strategies: Strategies &
      Readonly<Record<string, ManagedPassword<Data, C["Type"], RegistrationId, ClaimsId>>>;
  },
  options: ManagedOptions,
) => {
  const profile = "accounts/profile";
  const decodeClaims = Schema.decodeUnknownEffect(Schema.toType(auth.claims));

  const accounts = Object.entries(auth.strategies).map(([name, password]) => {
    const registration = makePasswordRegistration(
      password.RegistrationAuthority,
      password.persistence.moduleId,
    );

    const provisioning = Layer.succeed(registration.Provisioning, {
      create: Effect.fnUntraced(function* (input: {
        readonly identifier: LoginIdentifier;
        readonly registration: Data;
      }) {
        const tx = yield* Transaction;

        const claims = yield* decodeClaims(input.registration).pipe(
          Effect.mapError(() => Password.PasswordUnavailable.make({})),
        );

        const subjectId = SubjectId.make(yield* tx.id);

        yield* tx.put(auth.claims, profile, subjectId, claims);
        yield* tx.put(Subject, identityPartitions.subjects, subjectId, {
          subjectId,
          active: true,
          securityRevision: Sessions.SecurityRevision.make(yield* tx.id),
          requirement: options.requirements.signIn,
          actionRequirement: options.requirements.actions ?? options.requirements.signIn,
        });

        return subjectId;
      }),
    });

    const claims = Layer.effect(
      password.SessionClaims,
      Effect.gen(function* () {
        const store = yield* DocumentStore;

        return {
          resolve: Effect.fnUntraced(function* ({ subjectId }: { readonly subjectId: SubjectId }) {
            return yield* store
              .transaction(
                Effect.gen(function* () {
                  const tx = yield* Transaction;
                  const value = yield* tx.get(auth.claims, profile, subjectId);

                  if (value === undefined) return yield* Password.PasswordUnavailable.make({});

                  return value;
                }),
              )
              .pipe(Effect.mapError(() => Password.PasswordUnavailable.make({})));
          }),
        };
      }),
    );

    return {
      name,
      Provisioning: registration.Provisioning,
      layer: Layer.mergeAll(
        defaultLayer(
          password.RegistrationAuthority,
          registration.layer.pipe(
            Layer.provide(defaultLayer(registration.Provisioning, provisioning)),
          ),
        ),
        defaultLayer(password.SessionClaims, claims),
      ),
    };
  });

  const sessions = makeSessions(auth.claims, auth.sessions);

  const session = <I, S>(key: Context.Key<I, S>) =>
    defaultLayer(key, Layer.effect(key, key).pipe(Layer.provide(sessions)));

  // The entries retain the caller's strategy names; this only restores Object.fromEntries' lost keys.
  const provisioning = Object.fromEntries(
    accounts.map((account) => [account.name, account.Provisioning]),
  ) as {
    readonly [K in keyof Strategies]: ProvisioningKey<Strategies[K]>;
  };

  return {
    provisioning,
    layer: (ctx: ActionContext["Service"], functions: DocumentFunctions["Service"]) => {
      const documents = defaultLayer(DocumentStore, DocumentStore.layer(auth.namespace)).pipe(
        Layer.provide([
          defaultLayer(ActionContext, Layer.succeed(ActionContext, ctx)),
          defaultLayer(DocumentFunctions, Layer.succeed(DocumentFunctions, functions)),
        ]),
      );

      return Layer.mergeAll(
        defaultLayer(Password.PasswordPersistence, PasswordPersistence.layer),
        defaultLayer(Proofs.ProofPersistence, ProofPersistence.layer),
        session(Sessions.AuthenticationAuthority),
        session(auth.sessions.StatefulSessionPersistence),
        session(auth.sessions.SessionRepository),
        session(auth.sessions.PendingAuthentication),
        session(auth.sessions.SignedSessionValidity),
        ...accounts.map((account) => account.layer),
      ).pipe(Layer.provideMerge(documents));
    },
  };
};
