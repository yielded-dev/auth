import type { OAuthKernel } from "@yielded/auth-persistence/Adapter";

import { oauthKernel } from "./oauth-kernel";

export const sqlClientOAuthStandaloneGuard: OAuthKernel["target"]["sqlClientOAuthStandaloneGuard"] =
  oauthKernel.target.sqlClientOAuthStandaloneGuard;

export const makeTargetOAuthSignInServices: OAuthKernel["target"]["makeTargetOAuthSignInServices"] =
  oauthKernel.target.makeTargetOAuthSignInServices;

export const makeTargetOAuthRegistrationIntentServices: OAuthKernel["target"]["makeTargetOAuthRegistrationIntentServices"] =
  oauthKernel.target.makeTargetOAuthRegistrationIntentServices;

export const makeTargetOAuthRegistrationServices: OAuthKernel["target"]["makeTargetOAuthRegistrationServices"] =
  oauthKernel.target.makeTargetOAuthRegistrationServices;

export const coordinateTargetOAuthRegistration: OAuthKernel["target"]["coordinateTargetOAuthRegistration"] =
  oauthKernel.target.coordinateTargetOAuthRegistration;

export const coordinateTargetOAuthSignIn: OAuthKernel["target"]["coordinateTargetOAuthSignIn"] =
  oauthKernel.target.coordinateTargetOAuthSignIn;

export const coordinateTargetOAuthRegistrationIntents: OAuthKernel["target"]["coordinateTargetOAuthRegistrationIntents"] =
  oauthKernel.target.coordinateTargetOAuthRegistrationIntents;

export const coordinateTargetOAuthAccounts: OAuthKernel["target"]["coordinateTargetOAuthAccounts"] =
  oauthKernel.target.coordinateTargetOAuthAccounts;

export const makeTargetOAuthAccountsServices: OAuthKernel["target"]["makeTargetOAuthAccountsServices"] =
  oauthKernel.target.makeTargetOAuthAccountsServices;

export const oauthAccountsPersistenceLayer: OAuthKernel["target"]["oauthAccountsPersistenceLayer"] =
  oauthKernel.target.oauthAccountsPersistenceLayer;

export const oauthSignInPersistenceLayer: OAuthKernel["target"]["oauthSignInPersistenceLayer"] =
  oauthKernel.target.oauthSignInPersistenceLayer;

export const oauthRegistrationIntentsLayer: OAuthKernel["target"]["oauthRegistrationIntentsLayer"] =
  oauthKernel.target.oauthRegistrationIntentsLayer;

export const oauthRegistrationAuthorityLayer: OAuthKernel["target"]["oauthRegistrationAuthorityLayer"] =
  oauthKernel.target.oauthRegistrationAuthorityLayer;

export type {
  OAuthTargetConfiguration,
  OAuthCoordinatorError,
  OAuthExecution,
} from "@yielded/auth-persistence/Adapter";
