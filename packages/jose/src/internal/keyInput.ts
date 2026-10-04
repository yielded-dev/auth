import { Predicate } from "effect";

/** Copy only own fields, evaluating accessors once before Schema validation. */
export const object = (input: unknown): unknown => {
  if (!Predicate.isObject(input)) return input;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const copy: Record<string, unknown> = {};

  Object.setPrototypeOf(copy, null);
  for (const name of Object.getOwnPropertyNames(descriptors)) {
    const descriptor = descriptors[name];

    copy[name] = Object.hasOwn(descriptor, "value")
      ? descriptor.value
      : descriptor.get?.call(input);
  }

  return copy;
};

const array = (input: ReadonlyArray<unknown>): Array<unknown> => {
  const length = input.length;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const copy: Array<unknown> = [];

  for (let index = 0; index < length; index++) {
    const descriptor = Object.hasOwn(descriptors, index) ? descriptors[index] : undefined;

    copy[index] =
      descriptor === undefined
        ? undefined
        : Object.hasOwn(descriptor, "value")
          ? descriptor.value
          : descriptor.get?.call(input);
  }

  return copy;
};

export const jwk = (input: unknown): unknown => {
  const copy = object(input);

  if (Predicate.isObject(copy) && Array.isArray(copy.key_ops)) copy.key_ops = array(copy.key_ops);

  return copy;
};

export const keySet = (input: unknown): unknown => {
  const copy = object(input);

  if (Predicate.isObject(copy) && Array.isArray(copy.keys)) copy.keys = array(copy.keys).map(jwk);

  return copy;
};

/** Struct decoding creates ordinary objects; detach owned output as well. */
export const detach = <A>(value: A): A => {
  if (Predicate.isObject(value)) Object.setPrototypeOf(value, null);

  return value;
};
