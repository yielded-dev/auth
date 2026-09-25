/* eslint-disable import/extensions -- Noble public ESM entrypoints. */
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { TokenDigest } from "@yielded/auth/Schema";
import { Encoding } from "effect";
const encoder = new TextEncoder();

export const randomId = () => Encoding.encodeBase64Url(randomBytes(32));

export const digest = (value: string) =>
  TokenDigest.make(Encoding.encodeBase64Url(sha256(encoder.encode(value))));
