import type { OAuthKernel } from "@yielded/auth-persistence/Adapter";

import { oauthKernel } from "./oauth-kernel";

export const makeTargetOAuthConnectedServices: OAuthKernel["connectedTarget"]["makeTargetOAuthConnectedServices"] =
  oauthKernel.connectedTarget.makeTargetOAuthConnectedServices;

export const makeTargetOAuthConnectedRevocationServices: OAuthKernel["connectedTarget"]["makeTargetOAuthConnectedRevocationServices"] =
  oauthKernel.connectedTarget.makeTargetOAuthConnectedRevocationServices;

export const coordinateTargetOAuthConnected: OAuthKernel["connectedTarget"]["coordinateTargetOAuthConnected"] =
  oauthKernel.connectedTarget.coordinateTargetOAuthConnected;

export const coordinateTargetOAuthConnectedRevocations: OAuthKernel["connectedTarget"]["coordinateTargetOAuthConnectedRevocations"] =
  oauthKernel.connectedTarget.coordinateTargetOAuthConnectedRevocations;

export const oauthConnectedPersistenceLayer: OAuthKernel["connectedTarget"]["oauthConnectedPersistenceLayer"] =
  oauthKernel.connectedTarget.oauthConnectedPersistenceLayer;

export const oauthConnectedRevocationsLayer: OAuthKernel["connectedTarget"]["oauthConnectedRevocationsLayer"] =
  oauthKernel.connectedTarget.oauthConnectedRevocationsLayer;
