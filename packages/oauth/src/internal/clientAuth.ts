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

export const wipeApplied = (applied: ClientAuth.Applied): void => {
  if (!Predicate.isObject(applied)) return;
  if (Predicate.isObject(applied.headers)) {
    for (const value of Object.values(applied.headers)) {
      if (Redacted.isRedacted(value) && ephemeralRedacted.has(value as Redacted.Redacted<string>)) {
        Redacted.wipeUnsafe(value);
      }
    }
  }
  if (Array.isArray(applied.form)) {
    for (const entry of applied.form) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      const value: unknown = entry[1];

      if (Redacted.isRedacted(value) && ephemeralRedacted.has(value as Redacted.Redacted<string>)) {
        Redacted.wipeUnsafe(value);
      }
    }
  }
};
