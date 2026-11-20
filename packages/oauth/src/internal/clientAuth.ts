import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";

import type * as ClientAuth from "../ClientAuth.ts";

export const TypeId = "~effect/oauth/ClientAuth/Method" as const;

// Tracks per-request Redacted values allocated by built-in methods so request
// assembly can wipe them after encoding without touching caller-owned
// `Redacted` values returned by custom `ClientAuth.make` implementations.
const ephemeralRedacted = new WeakSet<Redacted.Redacted<string>>();

export const makeEphemeral = (value: string): Redacted.Redacted<string> => {
  const redacted = Redacted.make(value);

  ephemeralRedacted.add(redacted);

  return redacted;
};

export const registerEphemeral = (redacted: Redacted.Redacted<string>): void => {
  ephemeralRedacted.add(redacted);
};

export const isMethod = (u: unknown): u is ClientAuth.Method<unknown> =>
  Predicate.isObject(u) &&
  Predicate.hasProperty(u, TypeId) &&
  Predicate.hasProperty(u, "name") &&
  Predicate.isString(u.name) &&
  Predicate.hasProperty(u, "apply") &&
  Predicate.isFunction(u.apply);

const wipeDataValue = (value: unknown): void => {
  if (Redacted.isRedacted(value) && ephemeralRedacted.has(value as Redacted.Redacted<string>)) {
    Redacted.wipeUnsafe(value);
  }
};

/** Traverses own data descriptors on `applied.headers` and indexed own data
 * elements on `applied.form` without invoking getters, wiping every registered
 * ephemeral `Redacted` handle present in those slots even when validation
 * rejected `applied` while leaving caller-owned handles untouched. */
export const wipeApplied = (applied: ClientAuth.Applied): void => {
  if (!Predicate.isObject(applied)) return;

  const headersDesc = Object.getOwnPropertyDescriptor(applied, "headers");

  const headers =
    headersDesc !== undefined && "value" in headersDesc ? headersDesc.value : undefined;

  if (Predicate.isObject(headers)) {
    for (const key of Object.keys(headers)) {
      const descriptor = Object.getOwnPropertyDescriptor(headers, key);

      if (descriptor !== undefined && "value" in descriptor) {
        wipeDataValue(descriptor.value);
      }
    }
  }

  const formDesc = Object.getOwnPropertyDescriptor(applied, "form");
  const form = formDesc !== undefined && "value" in formDesc ? formDesc.value : undefined;

  if (Array.isArray(form)) {
    for (let i = 0; i < form.length; i++) {
      const entryDesc = Object.getOwnPropertyDescriptor(form, String(i));
      const entry = entryDesc !== undefined && "value" in entryDesc ? entryDesc.value : undefined;

      if (!Array.isArray(entry) || entry.length < 2) continue;
      const valueDesc = Object.getOwnPropertyDescriptor(entry, "1");

      if (valueDesc !== undefined && "value" in valueDesc) {
        wipeDataValue(valueDesc.value);
      }
    }
  }
};
