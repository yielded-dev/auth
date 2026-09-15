import { AuthContract } from "@yielded/auth/contracts";
import {
  EmailActionRequired,
  EmailCommandId,
  EmailMethodUnsupported,
  EmailRejected,
  EmailUnavailable,
} from "@yielded/auth/Email";
import { RequestBindingFlowId, RequestBindingPublic } from "@yielded/auth/Operations";
import * as PasskeyContract from "@yielded/auth/PasskeyContract";
import {
  NewPasswordRejected,
  PasswordActionRequired,
  PasswordCheckUnavailable,
  PasswordCommandId,
  PasswordMethodUnsupported,
  PasswordRejected,
  PasswordUnavailable,
} from "@yielded/auth/Password";
import {
  defaultProofPolicy,
  ProofContinuation,
  ProofContinuationId,
  ProofId,
  ProofReference,
  ProofRequestId,
  ProofRequestReceipt,
} from "@yielded/auth/Proofs";
import { Email } from "@yielded/auth/Schema";
import { AuthenticationFlowId, SessionInvalidationWindow } from "@yielded/auth/Sessions";
import { Schema } from "effect";

export const minimumPasswordLength = 8;
export const emailProofPolicy = defaultProofPolicy;

export const Registration = Schema.Struct({
  displayName: Schema.NonEmptyString.check(Schema.isMaxLength(80)),
});

export const Claims = Schema.Struct({
  displayName: Schema.String,
  email: Email,
  emailVerified: Schema.Boolean,
});

const email = Schema.String.check(Schema.isMaxLength(320)).pipe(Schema.decodeTo(Email));
const password = Schema.RedactedFromValue(Schema.String.check(Schema.isMaxLength(4096)));
const secret = Schema.RedactedFromValue(Schema.String.check(Schema.isMaxLength(4096)));

const PasswordFailure = Schema.Union([
  PasswordRejected,
  PasswordUnavailable,
  PasswordActionRequired,
  PasswordMethodUnsupported,
  NewPasswordRejected,
  PasswordCheckUnavailable,
]);

const EmailFailure = Schema.Union([
  EmailRejected,
  EmailUnavailable,
  EmailActionRequired,
  EmailMethodUnsupported,
]);

const mutationResult = Schema.Struct({ invalidation: SessionInvalidationWindow });
const continuationResult = Schema.Struct({ continuation: ProofContinuation });
const resetBase = { flowId: AuthenticationFlowId, email };
const verifyBase = { flowId: RequestBindingFlowId, commandId: EmailCommandId, email };
const passkeys = PasskeyContract.makeManagement("customers/passkeys").operations;

export const AuthApi = AuthContract.make("customers", {
  claims: Claims,
  actions: (sessions) => ({
    passwordSignIn: AuthContract.passwordSignIn(sessions, { strategy: "password" }),
    passkeySignIn: AuthContract.fromOperation(
      PasskeyContract.make("customers/passkey", sessions).operations.Begin,
      {
        strategy: "passkey",
        method: "signIn",
      },
    ),
    completePasskeySignIn: AuthContract.fromOperation(
      PasskeyContract.make("customers/passkey", sessions).operations.Complete,
      {
        strategy: "passkey",
        method: "completeSignIn",
        requestFields: { bindingCredential: "request-binding" },
        subject: {
          fromSuccess: (result) =>
            result._tag === "Authenticated" ? result.session.subjectId : undefined,
        },
      },
    ),
    enrollPasskey: AuthContract.fromOperation(passkeys.Begin, { strategy: "passkeys" }),
    completePasskeyEnrollment: AuthContract.fromOperation(passkeys.Complete, {
      strategy: "passkeys",
      requestFields: { bindingCredential: "request-binding" },
    }),
    listPasskeys: AuthContract.fromOperation(passkeys.List, {
      strategy: "passkeys",
      mode: "query",
    }),
    renamePasskey: AuthContract.fromOperation(passkeys.Rename, { strategy: "passkeys" }),
    register: AuthContract.action({
      payload: Schema.Struct({
        requestId: PasswordCommandId,
        email,
        newPassword: password,
        registration: Registration,
      }),
      success: Schema.Union([
        Schema.TaggedStruct("RegistrationAccepted", {}),
        Schema.TaggedStruct("ProvisioningPending", { reference: Schema.String }),
      ]),
      error: PasswordFailure,
      mode: "mutation",
      replay: "idempotent",
      strategy: "password",
    }),
    requestReset: AuthContract.action({
      payload: Schema.Struct({ ...resetBase, requestId: ProofRequestId, locale: Schema.String }),
      success: ProofRequestReceipt,
      error: PasswordFailure,
      mode: "mutation",
      replay: "idempotent",
      strategy: "password",
    }),
    verifyReset: AuthContract.action({
      payload: Schema.Struct({ ...resetBase, reference: ProofReference, secret }),
      success: continuationResult,
      error: PasswordFailure,
      mode: "mutation",
      replay: "single-use",
      credentials: true,
      strategy: "password",
    }),
    completeReset: AuthContract.action({
      payload: Schema.Struct({
        ...resetBase,
        commandId: PasswordCommandId,
        continuationId: ProofContinuationId,
        newPassword: password,
      }),
      success: mutationResult,
      error: PasswordFailure,
      mode: "mutation",
      replay: "single-use",
      credentials: true,
      strategy: "password",
      requestFields: { credential: "proof-continuation" },
    }),
    beginEmailAddress: AuthContract.action({
      payload: Schema.Struct({ flowId: RequestBindingFlowId }),
      success: RequestBindingPublic,
      error: EmailFailure,
      mode: "mutation",
      credentials: true,
      strategy: "email",
    }),
    requestEmailVerification: AuthContract.action({
      payload: Schema.Struct({ ...verifyBase, requestId: ProofRequestId, locale: Schema.String }),
      success: ProofRequestReceipt,
      error: EmailFailure,
      mode: "mutation",
      replay: "idempotent",
      strategy: "email",
      requestFields: { requestBinding: "request-binding" },
    }),
    resendEmailVerification: AuthContract.action({
      payload: Schema.Struct({
        ...verifyBase,
        requestId: ProofRequestId,
        locale: Schema.String,
        supersedes: ProofId,
      }),
      success: ProofRequestReceipt,
      error: EmailFailure,
      mode: "mutation",
      replay: "idempotent",
      strategy: "email",
      requestFields: { requestBinding: "request-binding" },
    }),
    verifyEmailAddress: AuthContract.action({
      payload: Schema.Struct({ ...verifyBase, reference: ProofReference, secret }),
      success: continuationResult,
      error: EmailFailure,
      mode: "mutation",
      replay: "single-use",
      credentials: true,
      strategy: "email",
      requestFields: { requestBinding: "request-binding" },
    }),
    completeEmailVerification: AuthContract.action({
      payload: Schema.Struct({ ...verifyBase, continuationId: ProofContinuationId }),
      success: Schema.Struct({ invalidation: Schema.optionalKey(SessionInvalidationWindow) }),
      error: EmailFailure,
      mode: "mutation",
      replay: "single-use",
      credentials: true,
      strategy: "email",
      requestFields: { requestBinding: "request-binding", credential: "proof-continuation" },
    }),
  }),
});
