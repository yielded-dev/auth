import { DateTime, Duration, Effect, Option, Redacted, Schema } from "effect";

import { OAuthConnectionStore } from "../../oauth/OAuthConnectionStore";
import { OAuthConnection, OAuthIdentity, OAuthProviderKey, OAuthTokens } from "../../oauth/schema";
import { check, decodeSubjectId } from "./support";

// Contract checks a downstream (typically encrypting) `OAuthConnectionStore`
// adapter must pass: keyed round-trips that preserve the redacted token
// values, replacement on put, removal, and isolation across subjects and
// providers. Run each case with `it.effect`.

export interface OAuthConnectionStoreConformanceCase {
  readonly name: string;
  readonly run: Effect.Effect<void, never, OAuthConnectionStore>;
}

const decodeOAuthProviderKey = Schema.decodeSync(OAuthProviderKey);

const conformanceProvider = decodeOAuthProviderKey("conformance");
const otherConformanceProvider = decodeOAuthProviderKey("conformance-other");

const makeOAuthConnection = (options: {
  readonly provider?: OAuthProviderKey;
  readonly subject: string;
  readonly accessToken: string;
  readonly refreshToken?: string;
}): Effect.Effect<OAuthConnection> =>
  Effect.map(DateTime.now, (now) => {
    const provider = options.provider ?? conformanceProvider;

    return OAuthConnection.make({
      provider,
      subjectId: decodeSubjectId(options.subject),
      identity: OAuthIdentity.make({
        provider,
        providerAccountId: `account:${options.subject}`,
        handle: Option.some(options.subject),
      }),
      tokens: OAuthTokens.make({
        accessToken: Redacted.make(options.accessToken),
        tokenType: "bearer",
        accessTokenExpiresAt: Option.some(DateTime.addDuration(now, Duration.hours(8))),
        refreshToken:
          options.refreshToken === undefined
            ? Option.none()
            : Option.some(Redacted.make(options.refreshToken)),
        refreshTokenExpiresAt: Option.none(),
        scope: Option.none(),
      }),
      connectedAt: now,
      updatedAt: now,
    });
  });

const oauthConnectionCase = <CaseError>(
  name: string,
  run: Effect.Effect<void, CaseError, OAuthConnectionStore>,
): OAuthConnectionStoreConformanceCase => ({ name, run: Effect.orDie(run) });

export const oauthConnectionStoreConformanceCases: ReadonlyArray<OAuthConnectionStoreConformanceCase> =
  [
    oauthConnectionCase(
      "put and get round-trip the connection including token values",
      Effect.gen(function* () {
        const store = yield* OAuthConnectionStore;

        const connection = yield* makeOAuthConnection({
          subject: "roundtrip",
          accessToken: "access-roundtrip",
          refreshToken: "refresh-roundtrip",
        });

        yield* store.put(connection);
        const loaded = yield* store.get(conformanceProvider, connection.subjectId);

        yield* check(Option.isSome(loaded), "get must return the stored connection");
        if (Option.isSome(loaded)) {
          yield* check(
            Redacted.value(loaded.value.tokens.accessToken) === "access-roundtrip" &&
              Option.isSome(loaded.value.tokens.refreshToken) &&
              Redacted.value(loaded.value.tokens.refreshToken.value) === "refresh-roundtrip",
            "token values must survive the round-trip exactly",
          );
          yield* check(
            loaded.value.identity.providerAccountId === "account:roundtrip",
            "the identity must survive the round-trip",
          );
        }
      }),
    ),

    oauthConnectionCase(
      "put replaces the existing connection for the same key",
      Effect.gen(function* () {
        const store = yield* OAuthConnectionStore;

        yield* store.put(
          yield* makeOAuthConnection({ subject: "replace", accessToken: "access-before" }),
        );
        yield* store.put(
          yield* makeOAuthConnection({ subject: "replace", accessToken: "access-after" }),
        );
        const loaded = yield* store.get(conformanceProvider, decodeSubjectId("replace"));

        yield* check(
          Option.isSome(loaded) &&
            Redacted.value(loaded.value.tokens.accessToken) === "access-after",
          "put must replace the previous connection",
        );
      }),
    ),

    oauthConnectionCase(
      "remove deletes the connection and is idempotent",
      Effect.gen(function* () {
        const store = yield* OAuthConnectionStore;
        const subjectId = decodeSubjectId("remove");

        yield* store.put(
          yield* makeOAuthConnection({ subject: "remove", accessToken: "access-remove" }),
        );
        yield* store.remove(conformanceProvider, subjectId);
        const loaded = yield* store.get(conformanceProvider, subjectId);

        yield* check(Option.isNone(loaded), "a removed connection must not be readable");
        yield* store.remove(conformanceProvider, subjectId);
      }),
    ),

    oauthConnectionCase(
      "connections are isolated by subject and by provider",
      Effect.gen(function* () {
        const store = yield* OAuthConnectionStore;

        yield* store.put(
          yield* makeOAuthConnection({ subject: "isolation-a", accessToken: "access-a" }),
        );
        yield* store.put(
          yield* makeOAuthConnection({ subject: "isolation-b", accessToken: "access-b" }),
        );
        yield* store.put(
          yield* makeOAuthConnection({
            provider: otherConformanceProvider,
            subject: "isolation-a",
            accessToken: "access-a-other",
          }),
        );
        const first = yield* store.get(conformanceProvider, decodeSubjectId("isolation-a"));
        const second = yield* store.get(conformanceProvider, decodeSubjectId("isolation-b"));
        const other = yield* store.get(otherConformanceProvider, decodeSubjectId("isolation-a"));

        yield* check(
          Option.isSome(first) && Redacted.value(first.value.tokens.accessToken) === "access-a",
          "subject A must read its own connection",
        );
        yield* check(
          Option.isSome(second) && Redacted.value(second.value.tokens.accessToken) === "access-b",
          "subject B must read its own connection",
        );
        yield* check(
          Option.isSome(other) &&
            Redacted.value(other.value.tokens.accessToken) === "access-a-other",
          "the same subject on another provider must read that provider's connection",
        );
      }),
    ),
  ];
