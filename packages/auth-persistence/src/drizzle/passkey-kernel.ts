import { makePasskeyKernel } from "../internal/passkey-kernel";
import { drizzleQueryOperations } from "./query-operations";
export const passkeyKernel = makePasskeyKernel(drizzleQueryOperations);
