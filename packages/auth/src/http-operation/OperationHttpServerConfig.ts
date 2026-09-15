import { Context, Effect, Layer, Schema } from "effect";
import { Cookies } from "effect/unstable/http";

import type { CredentialSlot } from "../operations/credentials";
import { headerName, origin } from "./configuration-schema";
import { OperationHttpConfigurationError } from "./errors";
import { credentialSlots, type OperationCookie, type OperationHttpConfiguration } from "./models";

export class OperationHttpServerConfig extends Context.Service<
  OperationHttpServerConfig,
  OperationHttpConfiguration
>()("effect-auth/OperationHttpServerConfig") {}

const cookie = Schema.Struct({
  name: Schema.NonEmptyString,
  path: Schema.String.check(Schema.isStartsWith("/")),
  secure: Schema.Boolean,
  sameSite: Schema.Literals(["lax", "strict", "none"]),
  domain: Schema.optionalKey(Schema.String),
});

export const configurationLayer = (input: OperationHttpConfiguration) =>
  Layer.effect(
    OperationHttpServerConfig,
    Effect.try({
      try: () => {
        if (
          input.trustedOrigins.length === 0 ||
          !input.trustedOrigins.every(Schema.is(origin)) ||
          !Schema.is(headerName)(input.csrfHeader) ||
          input.csrfValue.length < 1 ||
          input.csrfValue.length > 128 ||
          !Number.isSafeInteger(input.maximumBodyBytes) ||
          input.maximumBodyBytes < 1 ||
          input.maximumBodyBytes > 1048576 ||
          !Number.isSafeInteger(input.maximumUrlBytes) ||
          input.maximumUrlBytes < 1 ||
          input.maximumUrlBytes > 16384
        )
          throw new Error();
        if (typeof input.publicOrigin === "string" && !Schema.is(origin)(input.publicOrigin))
          throw new Error();
        const names = new Set<string>();

        const cookies = Object.fromEntries(
          credentialSlots.map((slot) => {
            const value = Schema.decodeSync(cookie)(input.cookies[slot]);

            if (
              names.has(value.name) ||
              (value.sameSite === "none" && !value.secure) ||
              (value.name.startsWith("__Secure-") && !value.secure) ||
              (value.name.startsWith("__Host-") &&
                (!value.secure || value.path !== "/" || value.domain !== undefined))
            )
              throw new Error();
            names.add(value.name);
            Cookies.makeCookieUnsafe(value.name, "probe", { ...value, httpOnly: true });

            return [slot, Object.freeze(value)];
          }),
        ) as unknown as OperationHttpConfiguration["cookies"];

        if (input.native !== undefined) {
          const native = input.native;

          const request = [
            native.modeHeader,
            ...credentialSlots.map((slot) => native.requestHeaders[slot]),
          ];

          const response = credentialSlots.map((slot) => native.responseHeaders[slot]);

          if (
            [...request, ...response].some((name) => !Schema.is(headerName)(name)) ||
            new Set(request).size !== request.length ||
            new Set(response).size !== response.length ||
            request.some((name) => ["origin", "cookie", "host", input.csrfHeader].includes(name)) ||
            response.some((name) => ["set-cookie", "location", "content-type"].includes(name))
          )
            throw new Error();
        }

        return Object.freeze({
          ...input,
          cookies,
          trustedOrigins: Object.freeze([...input.trustedOrigins]),
          ...(input.native === undefined
            ? {}
            : {
                native: Object.freeze({
                  ...input.native,
                  requestHeaders: Object.freeze({ ...input.native.requestHeaders }),
                  responseHeaders: Object.freeze({ ...input.native.responseHeaders }),
                }),
              }),
        });
      },
      catch: () => OperationHttpConfigurationError.make({ reason: "cookies" }),
    }),
  );

export const cookieConfiguration = (input: {
  readonly prefix: string;
  readonly secure: boolean;
  readonly path?: string;
  readonly sameSite?: OperationCookie["sameSite"];
}): OperationHttpConfiguration["cookies"] =>
  Object.fromEntries(
    credentialSlots.map((slot) => [
      slot,
      {
        name: `${input.prefix}${slot}`,
        path: input.path ?? "/",
        secure: input.secure,
        sameSite: input.sameSite ?? "lax",
      },
    ]),
  ) as unknown as OperationHttpConfiguration["cookies"];

export const headerConfiguration = (prefix: string): Readonly<Record<CredentialSlot, string>> =>
  Object.fromEntries(credentialSlots.map((slot) => [slot, `${prefix}${slot}`])) as Readonly<
    Record<CredentialSlot, string>
  >;
