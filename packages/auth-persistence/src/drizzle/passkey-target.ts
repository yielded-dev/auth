import { passkeyKernel } from "./passkey-kernel";

export type {
  PasskeyTargetConfiguration,
  PasskeyCoordinatorError,
  PasskeyExecution,
} from "../internal/passkey/target";

export const {
  sqlClientPasskeyStandaloneGuard,
  makePasskeyExecution,
  capturedService,
  prepareValue,
  observationalContext,
  makePasskeyPersistence,
  capturedMapping,
  makeTargetPasskeyCredentials,
  makeTargetPasskeyEnrollmentContext,
  makeTargetPasskeyPersistence,
  makeTargetPasskeyRegistration,
  coordinateTargetPasskey,
  coordinateTargetPasskeyRegistration,
} = passkeyKernel.target;
