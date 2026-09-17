import {
  Cause,
  Context,
  Crypto,
  DateTime,
  Effect,
  Encoding,
  Layer,
  Redacted,
  Schema,
} from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";

import { cryptoLayer } from "../../auth/defaults";
import { origin as Origin } from "../../http-operation/configuration-schema";
import type { AuthOperationResult } from "../../operations/credentials";
import { RequestBindingFlowId } from "../../operations/requestBinding";
import { SubjectId, TokenDigest } from "../../Schema";
import { makeSessionSigningCodec, type SessionSigningKeyring } from "../../sessions/crypto";
import { SessionInvalid } from "../../sessions/errors";
import { SecurityRevision } from "../../sessions/models";
import {
  OAuthConnectedConfiguration,
  OAuthConnectedGrantResponse,
  OAuthConnectedProfile,
  OAuthConnectedTokenContext,
  OAuthConnectedBusy,
  OAuthConnectedReauthorizationRequired,
  OAuthGrantId,
} from "../connectedModels";
import type { OAuthConnectedProtocol } from "../OAuthConnectedProtocol";
import { OAuthConnectedTokenProtector } from "../OAuthConnectedTokenProtector";
import { OAuthTransactionProtector } from "../OAuthTransactionProtector";
import { OAuthRejected, OAuthUnavailable, OAuthConfigurationError } from "../signInErrors";
import type { OAuthVerifiedExternalIdentity } from "../signInModels";
import {
  OAuthCallbackId,
  OAuthCodeResponse,
  OAuthCommandId,
  OAuthModuleId,
  OAuthReturnTarget,
  OAuthSignInTransactionContext,
} from "../signInModels";
import { snapshotOAuth } from "../signInSnapshot";
import type { OAuthTransactionKeyring } from "../transactionEncryption";
import { FlowRecord, GrantRecord, Persistence } from "./models";

/** Provider adapters bind to the exact callback owned by this application.
 * The existing connected protocol owns provider verification and token handling.
 * Secrets remain in the adapter Layer, never in the shared application contract.
 */
export interface Provider<E = never, R = never> {
  readonly configure: (callbackUrl: string) => Effect.Effect<
    {
      readonly profile: OAuthConnectedProfile;
      readonly protocol: OAuthConnectedProtocol["Service"];
    },
    E,
    R
  >;
}

export interface SessionOptions {
  readonly origin: string;
  readonly sessionKeys: SessionSigningKeyring;
}

export interface Options<E, R> extends SessionOptions {
  readonly provider: Provider<E, R>;
  readonly transactionKeys: OAuthTransactionKeyring;
  readonly tokenKeys: OAuthTransactionKeyring;
}

const now = DateTime.now.pipe(Effect.map(DateTime.toEpochMillis));
const encoder = new TextEncoder();

const randomSource = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;

  const bytes = yield* crypto
    .randomBytes(32)
    .pipe(Effect.mapError(() => OAuthUnavailable.make({})));

  const value = Encoding.encodeBase64Url(bytes);

  bytes.fill(0);

  return value;
});

const digestSource = Effect.fn("OAuthApp.digest")(function* (value: string) {
  const crypto = yield* Crypto.Crypto;

  const bytes = yield* crypto
    .digest("SHA-256", encoder.encode(value))
    .pipe(Effect.mapError(() => OAuthUnavailable.make({})));

  return Encoding.encodeBase64Url(bytes);
});

const policySchema = Schema.Struct({
  id: Schema.String.check(Schema.isPattern(/^[a-z][a-z0-9-]{0,47}$/)),
  sessionLifetimeMillis: Schema.Int.check(Schema.isBetween({ minimum: 1000, maximum: 2592000000 })),
  flowLifetimeMillis: Schema.Int.check(Schema.isBetween({ minimum: 1000, maximum: 900000 })),
  exchangeTimeoutMillis: Schema.Int.check(Schema.isBetween({ minimum: 1000, maximum: 120000 })),
  returnTargets: Schema.NonEmptyArray(OAuthReturnTarget),
});

type Failure =
  | OAuthRejected
  | OAuthUnavailable
  | OAuthConnectedBusy
  | OAuthConnectedReauthorizationRequired
  | SessionInvalid;

/** One guest authorization establishes an application session and a provider
 * connection. Sessions are signed and verified offline; flow and grant claims
 * remain durable. This does not install an OAuth authorization server.
 */
export const make = <
  const Id extends string,
  Claims extends Schema.Codec<unknown, unknown, never, never>,
>(
  id: Id,
  input: {
    readonly claims: Claims;
    readonly returnTargets: readonly [string, ...string[]];
    readonly sessionLifetimeMillis?: number;
    readonly flowLifetimeMillis?: number;
    readonly exchangeTimeoutMillis?: number;
  },
) => {
  const options = { ...input, returnTargets: [...input.returnTargets] };
  const claims: Schema.Codec<Claims["Type"], Claims["Encoded"], never, never> = options.claims;

  const Session = Schema.Struct({
    subjectId: SubjectId,
    grantId: OAuthGrantId,
    claims,
    issuedAtMillis: Schema.Natural,
    expiresAtMillis: Schema.Natural,
  });

  type Session = typeof Session.Type;
  const Account = Schema.Struct({ subjectId: SubjectId, claims });

  const Accounts = Context.Service<
    { readonly app: Id; readonly kind: "accounts" },
    {
      /** Application policy: check invitations/status and select a stable subject.
       * Only verified provider identity/profile is supplied. Never merge by email.
       * A confirmed result authorizes this sign-in with the returned claim snapshot.
       */
      readonly resolve: (
        identity: typeof OAuthVerifiedExternalIdentity.Type,
      ) => Effect.Effect<typeof Account.Type, OAuthRejected | OAuthUnavailable>;
    }
  >()(`effect-auth/OAuthApp/${id}/Accounts`);

  const Sessions = Context.Service<
    { readonly app: Id; readonly kind: "sessions" },
    {
      readonly verify: (
        credential: Redacted.Redacted<string>,
      ) => Effect.Effect<Session, SessionInvalid | OAuthUnavailable>;
    }
  >()(`effect-auth/OAuthApp/${id}/Sessions`);

  const Service = Context.Service<
    { readonly app: Id; readonly kind: "application" },
    {
      readonly begin: (
        returnTarget?: string,
      ) => Effect.Effect<
        AuthOperationResult<{ readonly authorizationUrl: Redacted.Redacted<string> }>,
        Failure
      >;
      readonly complete: (
        binding: Redacted.Redacted<string>,
        response: URLSearchParams,
      ) => Effect.Effect<
        AuthOperationResult<{ readonly session: Session; readonly returnTarget: string }>,
        Failure
      >;
      /** Server-only capability. Obtain this reference from a verified session or
       * trusted application storage; never forward arbitrary caller-supplied IDs.
       * The callback runs once, with no automatic retry of its external work.
       */
      readonly withAccessToken: <A, E, R>(
        connection: Pick<Session, "subjectId" | "grantId">,
        use: (token: Redacted.Redacted<string>) => Effect.Effect<A, E, R>,
      ) => Effect.Effect<A, E | Failure, R>;
      /** Disable local API access. App sessions retain their original expiry. */
      readonly disconnect: (
        connection: Pick<Session, "subjectId" | "grantId">,
      ) => Effect.Effect<void, Failure>;
      readonly handle: (request: Request) => Effect.Effect<Response, never>;
    }
  >()(`effect-auth/OAuthApp/${id}`);

  const basePath = `/auth/${id}` as const;

  const paths = {
    signIn: `${basePath}/sign-in`,
    callback: `${basePath}/callback`,
    session: `${basePath}/session`,
    signOut: `${basePath}/sign-out`,
  } as const;

  const cookieName = `yielded-${id}-session`;
  const bindingName = `yielded-${id}-flow`;
  const moduleId = OAuthModuleId.make(`oauth-app/${id}`);

  const policy = () =>
    Schema.decodeUnknownEffect(policySchema)({
      id,
      returnTargets: options.returnTargets,
      sessionLifetimeMillis: options.sessionLifetimeMillis ?? 30 * 24 * 60 * 60 * 1000,
      flowLifetimeMillis: options.flowLifetimeMillis ?? 5 * 60 * 1000,
      exchangeTimeoutMillis: options.exchangeTimeoutMillis ?? 30_000,
    }).pipe(Effect.mapError(() => OAuthConfigurationError.make({ reason: "policy" })));

  const signing = Effect.fn("OAuthApp.signing")(function* (config: SessionOptions) {
    const configured = yield* policy();

    const origin = yield* Schema.decodeEffect(Origin)(config.origin).pipe(
      Effect.mapError(() => OAuthConfigurationError.make({ reason: "policy" })),
    );

    const Envelope = Schema.Struct({
      purpose: Schema.Literal("oauth-app-session/v1"),
      application: Schema.Literal(id),
      origin: Schema.Literal(origin),
      session: Session,
    });

    const codec = yield* makeSessionSigningCodec(Envelope, config.sessionKeys, 3800);

    const verify = Effect.fn("OAuthApp.verifySession")(
      function* (credential: Redacted.Redacted<string>) {
        const { session } = yield* codec.decode(credential);
        const time = yield* now;

        if (
          session.issuedAtMillis > time ||
          session.expiresAtMillis <= time ||
          session.expiresAtMillis <= session.issuedAtMillis ||
          session.expiresAtMillis - session.issuedAtMillis > configured.sessionLifetimeMillis
        )
          return yield* SessionInvalid.make({});

        return session;
      },
      Effect.catchTag("SessionUnavailable", () => Effect.fail(OAuthUnavailable.make({}))),
    );

    return {
      verify,
      encode: (session: Session) =>
        codec.encode({ purpose: "oauth-app-session/v1", application: id, origin, session }),
    };
  });

  const sessionLayer = (config: SessionOptions) =>
    Layer.effect(Sessions, signing(config)).pipe(Layer.provide(cryptoLayer));

  const layer = <E, R>(input: Options<E, R>) => {
    const config = { ...input };

    return Layer.effectContext(
      Effect.gen(function* () {
        const configured = yield* policy();
        const codec = yield* signing(config);
        const crypto = yield* Crypto.Crypto;
        const random = randomSource.pipe(Effect.provideService(Crypto.Crypto, crypto));

        const digest = (value: string) =>
          digestSource(value).pipe(Effect.provideService(Crypto.Crypto, crypto));

        const persistence = yield* Persistence;
        const accounts = yield* Accounts;
        const transactions = yield* OAuthTransactionProtector;
        const tokens = yield* OAuthConnectedTokenProtector;
        const callbackUrl = `${config.origin}${paths.callback}`;
        const provided = yield* config.provider.configure(callbackUrl);
        const profile = yield* snapshotOAuth(OAuthConnectedProfile, provided.profile);
        const protocol = provided.protocol;
        const callbackId = OAuthCallbackId.make(profile.provider);

        const bounded = <A, E2, R2>(effect: Effect.Effect<A, E2, R2>) =>
          effect.pipe(
            Effect.timeout(configured.exchangeTimeoutMillis),
            Effect.catchTag("TimeoutError", () => Effect.fail(OAuthUnavailable.make({}))),
          );

        const safe = <A, E2, R2>(effect: Effect.Effect<A, E2, R2>) =>
          effect.pipe(Effect.catchDefect(() => Effect.fail(OAuthUnavailable.make({}))));

        const store: Persistence["Service"] = {
          get: (...args) => bounded(persistence.get(...args)),
          insert: (...args) => bounded(persistence.insert(...args)),
          compareAndSet: (...args) => bounded(persistence.compareAndSet(...args)),
        };

        const load = (key: string) => store.get(id, key);

        const cas = (
          key: string,
          previous: FlowRecord | GrantRecord,
          next: FlowRecord | GrantRecord,
        ) => store.compareAndSet(id, key, previous.version, next);

        const check = (
          response: OAuthConnectedGrantResponse,
          configuration: OAuthConnectedConfiguration,
        ) =>
          Effect.gen(function* () {
            const grant = yield* snapshotOAuth(OAuthConnectedGrantResponse, response);

            if (
              grant.identity.provider !== configuration.provider ||
              grant.identity.issuer !== configuration.issuer ||
              profile.scopes.some((scope) => !grant.scopes.includes(scope)) ||
              profile.resources.some((resource) => !grant.resources.includes(resource)) ||
              (configuration.protocol === "oidc") !== (grant.material.continuation._tag === "Oidc")
            )
              return yield* OAuthRejected.make({});

            return grant;
          });

        const makeGrant = Effect.fn("OAuthApp.makeGrant")(function* (
          grant: OAuthConnectedGrantResponse,
          configuration: OAuthConnectedConfiguration,
          subjectId: SubjectId,
          grantId: typeof OAuthGrantId.Type,
        ) {
          const time = yield* now;
          const version = yield* random;

          const useUntilMillis = Math.min(
            grant.accessExpiresAtMillis ?? Infinity,
            time + configuration.profile.maximumAccessLifetimeMillis,
          );

          if (useUntilMillis <= time) return yield* OAuthRejected.make({});

          const refreshUntil =
            grant.material.refreshToken === undefined
              ? undefined
              : Math.min(
                  grant.refreshExpiresAtMillis ?? Infinity,
                  time +
                    (configuration.profile.maximumRefreshLifetimeMillis ??
                      30 * 24 * 60 * 60 * 1000),
                );

          const context = yield* snapshotOAuth(OAuthConnectedTokenContext, {
            namespace: "effect-auth/oauth-connected-token-context/v1",
            moduleId,
            subjectId,
            identity: grant.identity,
            configuration,
            grantId,
            grantVersion: SecurityRevision.make(version),
            tokenVersion: SecurityRevision.make(version),
            cohortGeneration: SecurityRevision.make(version),
            metadata: {
              scopes: grant.scopes,
              resources: grant.resources,
              obtainedAtMillis: time,
              useUntilMillis,
              ...(grant.accessExpiresAtMillis === undefined
                ? {}
                : { accessExpiresAtMillis: grant.accessExpiresAtMillis }),
              ...(grant.refreshExpiresAtMillis === undefined
                ? {}
                : { refreshExpiresAtMillis: grant.refreshExpiresAtMillis }),
              ...(refreshUntil === undefined ? {} : { refreshUseUntilMillis: refreshUntil }),
              ...(grant.profile === undefined ? {} : { profile: grant.profile }),
            },
          });

          return GrantRecord.make({
            _tag: "Grant",
            version,
            status: "Active",
            context,
            sealed: yield* tokens.seal({ context, material: grant.material }),
          });
        });

        const begin = Effect.fn("OAuthApp.begin")(function* (target: string | undefined) {
          const returnTarget = target ?? configured.returnTargets[0];

          if (!configured.returnTargets.some((target) => target === returnTarget))
            return yield* OAuthRejected.make({});
          const flowId = RequestBindingFlowId.make(yield* random);
          const binding = yield* random;

          const prepared = yield* bounded(
            protocol.prepareAuthorization({ profile, callbackId, flowId }),
          ).pipe(
            Effect.catchTag("OAuthProtocolRejected", () => Effect.fail(OAuthRejected.make({}))),
          );

          const configuration = yield* snapshotOAuth(
            OAuthConnectedConfiguration,
            prepared.configuration,
          );

          if (
            configuration.redirectUri !== callbackUrl ||
            configuration.provider !== profile.provider ||
            configuration.callbackId !== callbackId ||
            JSON.stringify(configuration.profile) !== JSON.stringify(profile)
          )
            return yield* OAuthUnavailable.make({});
          const time = yield* now;

          const context = yield* snapshotOAuth(OAuthSignInTransactionContext, {
            namespace: "effect-auth/oauth-sign-in-context/v1",
            moduleId,
            generation: 1,
            flowId,
            commandId: OAuthCommandId.make(flowId),
            ...configuration,
            returnTarget: OAuthReturnTarget.make(returnTarget),
            stateDigest: TokenDigest.make(yield* digest(Redacted.value(prepared.secrets.state))),
            requestBindingVerifier: TokenDigest.make(yield* digest(binding)),
            requestBindingExpiresAtMillis: time + configured.flowLifetimeMillis,
            issuedAtMillis: time,
            expiresAtMillis: time + configured.flowLifetimeMillis,
            claimLifetimeMillis: configured.exchangeTimeoutMillis,
          });

          const row = FlowRecord.make({
            _tag: "Flow",
            version: yield* random,
            status: "Pending",
            context,
            configuration,
            sealed: yield* transactions.seal({ context, secrets: prepared.secrets }),
            deadlineMillis: context.expiresAtMillis,
          });

          if (!(yield* store.insert(id, `flow/${flowId}`, row)))
            return yield* OAuthUnavailable.make({});

          return {
            value: { authorizationUrl: prepared.authorizationUrl },
            credentialCommands: [
              {
                _tag: "Issue" as const,
                slot: "request-binding" as const,
                credential: Redacted.make(`${flowId}.${binding}`),
                expiresAtMillis: context.expiresAtMillis,
              },
            ],
          };
        }, safe);

        const complete = Effect.fn("OAuthApp.complete")(function* (
          binding: Redacted.Redacted<string>,
          query: URLSearchParams,
        ) {
          const raw = Redacted.value(binding);

          if (!/^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(raw))
            return yield* OAuthRejected.make({});
          const [flowId, secret] = raw.split(".");
          const key = `flow/${flowId}`;
          const row = yield* load(key);
          const time = yield* now;

          if (
            row?._tag !== "Flow" ||
            row.status !== "Pending" ||
            row.sealed === undefined ||
            row.context.moduleId !== moduleId ||
            row.context.flowId !== flowId ||
            row.context.redirectUri !== callbackUrl ||
            row.context.expiresAtMillis <= time ||
            row.deadlineMillis <= time ||
            row.context.requestBindingVerifier !== (yield* digest(secret))
          )
            return yield* OAuthRejected.make({});
          const sealed = row.sealed;

          for (const name of ["state", "code", "error", "iss", "scope"])
            if (query.getAll(name).length > 1) return yield* OAuthRejected.make({});
          const state = query.get("state");

          if (
            state === null ||
            state.length > 2048 ||
            row.context.stateDigest !== (yield* digest(state))
          )
            return yield* OAuthRejected.make({});
          const issuer = query.get("iss");

          if (
            row.context.responseIssuerMode === "required"
              ? issuer !== row.context.issuer
              : issuer !== null
          )
            return yield* OAuthRejected.make({});

          const owned = FlowRecord.make({
            ...row,
            status: "Claimed",
            version: yield* random,
            deadlineMillis: time + configured.exchangeTimeoutMillis,
          });

          if (!(yield* cas(key, row, owned))) return yield* OAuthRejected.make({});

          const finish = store.compareAndSet(
            id,
            key,
            owned.version,
            FlowRecord.make({
              _tag: "Flow",
              status: "Finished",
              version: yield* random,
              context: owned.context,
              configuration: owned.configuration,
              deadlineMillis: owned.deadlineMillis,
            }),
          );

          const result = yield* bounded(
            Effect.gen(function* () {
              const code = query.get("code");
              const scope = query.get("scope");

              if (query.has("error") || code === null || code.length === 0)
                return yield* OAuthRejected.make({});

              const secrets = yield* transactions.open({
                context: row.context,
                sealed,
              });

              if (Redacted.value(secrets.state) !== state) return yield* OAuthRejected.make({});

              const response = yield* Schema.decodeEffect(OAuthCodeResponse)({
                _tag: "Code",
                state,
                code,
                ...(issuer === null ? {} : { issuer: row.context.issuer }),
                ...(scope === null ? {} : { scope }),
              }).pipe(Effect.mapError(() => OAuthRejected.make({})));

              const grant = yield* protocol
                .exchangeGrant({
                  configuration: row.configuration,
                  secrets,
                  response,
                  verificationStartedAt: DateTime.makeUnsafe(time),
                })
                .pipe(
                  Effect.flatMap((value) => check(value, row.configuration)),
                  Effect.catchTag("OAuthProtocolRejected", () =>
                    Effect.fail(OAuthRejected.make({})),
                  ),
                );

              const account = yield* accounts
                .resolve({
                  identity: grant.identity,
                  ...(grant.profile === undefined ? {} : { profile: grant.profile }),
                })
                .pipe(Effect.flatMap((value) => snapshotOAuth(Account, value)));

              const grantId = OAuthGrantId.make(
                yield* digest(
                  JSON.stringify([
                    id,
                    grant.identity.provider,
                    grant.identity.issuer,
                    row.configuration.profile.clientRegistrationId,
                    grant.identity.subject,
                  ]),
                ),
              );

              const grantKey = `grant/${grantId}`;
              const existing = yield* load(grantKey);

              if (
                existing !== undefined &&
                (existing._tag !== "Grant" || existing.context.subjectId !== account.subjectId)
              )
                return yield* OAuthRejected.make({});
              const next = yield* makeGrant(grant, row.configuration, account.subjectId, grantId);
              const issuedAtMillis = yield* now;

              const session = {
                subjectId: account.subjectId,
                claims: account.claims,
                grantId,
                issuedAtMillis,
                expiresAtMillis: issuedAtMillis + configured.sessionLifetimeMillis,
              };

              const credential = yield* codec
                .encode(session)
                .pipe(Effect.mapError(() => OAuthUnavailable.make({})));

              if (issuedAtMillis >= owned.deadlineMillis) return yield* OAuthUnavailable.make({});

              const saved =
                existing === undefined
                  ? yield* store.insert(id, grantKey, next)
                  : yield* cas(grantKey, existing, next);

              if (!saved) return yield* OAuthConnectedBusy.make({});
              if ((yield* now) >= owned.deadlineMillis) return yield* OAuthUnavailable.make({});

              return {
                value: { session, returnTarget: row.context.returnTarget },
                credentialCommands: [
                  { _tag: "Clear" as const, slot: "request-binding" as const },
                  {
                    _tag: "Issue" as const,
                    slot: "session" as const,
                    credential,
                    expiresAtMillis: session.expiresAtMillis,
                  },
                ],
              };
            }),
          ).pipe(Effect.ensuring(bounded(finish).pipe(Effect.ignore)));

          return result;
        }, safe);

        const connection = Effect.fn("OAuthApp.connection")(function* (
          reference: Pick<Session, "subjectId" | "grantId">,
        ) {
          const row = yield* load(`grant/${reference.grantId}`);

          if (
            row?._tag !== "Grant" ||
            row.context.moduleId !== moduleId ||
            row.context.grantId !== reference.grantId ||
            row.context.subjectId !== reference.subjectId ||
            row.status === "Disconnected" ||
            row.sealed === undefined
          )
            return yield* OAuthConnectedReauthorizationRequired.make({});
          if (row.status === "Refreshing") {
            if ((row.claimExpiresAtMillis ?? 0) > (yield* now))
              return yield* OAuthConnectedBusy.make({});

            return yield* OAuthConnectedReauthorizationRequired.make({});
          }

          return { ...row, sealed: row.sealed };
        });

        const access = Effect.fn("OAuthApp.access")(function* (
          reference: Pick<Session, "subjectId" | "grantId">,
        ) {
          const row = yield* connection(reference);
          const time = yield* now;

          if (
            time + row.context.configuration.profile.refreshAheadMillis <
            row.context.metadata.useUntilMillis
          )
            return yield* tokens
              .open({ context: row.context, sealed: row.sealed })
              .pipe(Effect.map((value) => value.accessToken));
          if (
            row.context.configuration.profile.refresh === "unsupported" ||
            (row.context.metadata.refreshUseUntilMillis ?? 0) <= time
          )
            return yield* OAuthConnectedReauthorizationRequired.make({});
          const material = yield* tokens.open({ context: row.context, sealed: row.sealed });

          if (material.refreshToken === undefined)
            return yield* OAuthConnectedReauthorizationRequired.make({});

          const claimed = GrantRecord.make({
            ...row,
            version: yield* random,
            status: "Refreshing",
            claimExpiresAtMillis: time + configured.exchangeTimeoutMillis,
          });

          const key = `grant/${reference.grantId}`;

          if (!(yield* cas(key, row, claimed))) return yield* OAuthConnectedBusy.make({});

          // A failed, interrupted or unknown refresh leaves this permanent claim.
          // Only a fresh user authorization can recover it; never reuse that token.
          const refreshed = yield* bounded(
            protocol.refreshGrant({
              context: row.context,
              material,
              verificationStartedAt: DateTime.makeUnsafe(time),
            }),
          ).pipe(
            Effect.flatMap((value) => check(value, row.context.configuration)),
            Effect.catchTag("OAuthProtocolRejected", () =>
              Effect.fail(OAuthConnectedReauthorizationRequired.make({})),
            ),
          );

          if (JSON.stringify(refreshed.identity) !== JSON.stringify(row.context.identity))
            return yield* OAuthRejected.make({});

          const next = yield* makeGrant(
            refreshed,
            row.context.configuration,
            reference.subjectId,
            reference.grantId,
          );

          if (!(yield* cas(key, claimed, next)))
            return yield* OAuthConnectedReauthorizationRequired.make({});

          return refreshed.material.accessToken;
        }, safe);

        const withAccessToken = <A, E2, R2>(
          reference: Pick<Session, "subjectId" | "grantId">,
          use: (token: Redacted.Redacted<string>) => Effect.Effect<A, E2, R2>,
        ) => Effect.flatMap(access(reference), use);

        const disconnect = Effect.fn("OAuthApp.disconnect")(function* (
          reference: Pick<Session, "subjectId" | "grantId">,
        ) {
          const key = `grant/${reference.grantId}`;
          const row = yield* load(key);

          if (
            row?._tag !== "Grant" ||
            row.context.subjectId !== reference.subjectId ||
            row.context.grantId !== reference.grantId ||
            row.context.moduleId !== moduleId
          )
            return yield* OAuthRejected.make({});
          if (row.status === "Disconnected") return;
          if (
            !(yield* cas(
              key,
              row,
              GrantRecord.make({
                _tag: "Grant",
                version: yield* random,
                status: "Disconnected",
                context: row.context,
              }),
            ))
          )
            return yield* OAuthConnectedBusy.make({});
        }, safe);

        const cookie = (name: string, value: string, age: number) =>
          `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, Math.floor(age / 1000))}${config.origin.startsWith("https:") ? "; Secure" : ""}`;

        const handle = Effect.fn("OAuthApp.handle")(
          function* (request: Request) {
            const url = new URL(request.url);
            const cookies = HttpServerRequest.fromWeb(request).cookies;

            const headers = new Headers({
              "cache-control": "no-store",
              "referrer-policy": "no-referrer",
            });

            if (url.origin !== config.origin) return new Response(null, { status: 400, headers });
            if (request.method === "GET" && url.pathname === paths.signIn) {
              const result = yield* begin(url.searchParams.get("returnTo") ?? undefined);
              const command = result.credentialCommands[0];

              headers.append(
                "set-cookie",
                cookie(
                  bindingName,
                  Redacted.value(command.credential),
                  command.expiresAtMillis - (yield* now),
                ),
              );
              headers.set("location", Redacted.value(result.value.authorizationUrl));

              return new Response(null, { status: 302, headers });
            }
            if (request.method === "GET" && url.pathname === paths.callback) {
              const binding = cookies[bindingName];

              if (binding === undefined) return yield* OAuthRejected.make({});
              const result = yield* complete(Redacted.make(binding), url.searchParams);

              for (const command of result.credentialCommands)
                headers.append(
                  "set-cookie",
                  cookie(
                    command.slot === "session" ? cookieName : bindingName,
                    command._tag === "Issue" ? Redacted.value(command.credential) : "",
                    command._tag === "Issue" ? command.expiresAtMillis - (yield* now) : 0,
                  ),
                );
              headers.set("location", `${config.origin}${result.value.returnTarget}`);

              return new Response(null, { status: 302, headers });
            }
            if (request.method === "GET" && url.pathname === paths.session) {
              const credential = cookies[cookieName];

              if (credential === undefined) return new Response(null, { status: 401, headers });
              const session = yield* codec.verify(Redacted.make(credential));

              const json = yield* Schema.encodeEffect(Schema.fromJsonString(Session))(session).pipe(
                Effect.mapError(() => OAuthUnavailable.make({})),
              );

              headers.set("content-type", "application/json");

              return new Response(json, { headers });
            }
            if (request.method === "POST" && url.pathname === paths.signOut) {
              if (request.headers.get("origin") !== config.origin)
                return yield* OAuthRejected.make({});
              headers.append("set-cookie", cookie(cookieName, "", 0));

              return new Response(null, { status: 204, headers });
            }

            return new Response(null, { status: 404, headers });
          },
          (effect) =>
            effect.pipe(
              Effect.catchTag("SessionInvalid", () =>
                Effect.succeed(
                  new Response(null, { status: 401, headers: { "cache-control": "no-store" } }),
                ),
              ),
              Effect.catchTag("OAuthUnavailable", () =>
                Effect.succeed(
                  new Response("Authentication is temporarily unavailable. Start a new sign-in.", {
                    status: 503,
                    headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" },
                  }),
                ),
              ),
              Effect.catchCause((cause) => {
                if (Cause.hasInterrupts(cause)) return Effect.interrupt;

                return Effect.succeed(
                  new Response("Authentication could not be completed. Start a new sign-in.", {
                    status: 400,
                    headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" },
                  }),
                );
              }),
            ),
        );

        return Context.make(Service, { begin, complete, withAccessToken, disconnect, handle }).pipe(
          Context.add(Sessions, { verify: codec.verify }),
        );
      }),
    ).pipe(
      Layer.provide(OAuthTransactionProtector.xchacha20poly1305(config.transactionKeys)),
      Layer.provide(OAuthConnectedTokenProtector.xchacha20poly1305(config.tokenKeys)),
      Layer.provide(cryptoLayer),
    );
  };

  const routes = Layer.unwrap(
    Effect.gen(function* () {
      const app = yield* Service;

      const route = (path: `/${string}`) =>
        HttpRouter.add(
          "*",
          path,
          Effect.gen(function* () {
            const request = yield* HttpServerRequest.HttpServerRequest;
            const response = yield* app.handle(yield* HttpServerRequest.toWeb(request));

            return HttpServerResponse.fromWeb(response);
          }),
        );

      return Layer.mergeAll(
        route(paths.signIn),
        route(paths.callback),
        route(paths.session),
        route(paths.signOut),
      );
    }),
  );

  return {
    Service,
    Sessions,
    Accounts,
    Session,
    Account,
    layer,
    sessionLayer,
    routes,
    paths,
    cookieName,
  };
};
