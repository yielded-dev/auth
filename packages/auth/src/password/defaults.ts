import { Layer } from "effect";

import { cryptoLayer, defaultLayer } from "../auth/defaults";
import { NewPasswordCheck } from "./NewPasswordCheck";
import { PasswordHashing } from "./PasswordHashing";
import { PasswordKdfAdmission } from "./PasswordKdfAdmission";

const admissionLayer = defaultLayer(PasswordKdfAdmission, PasswordKdfAdmission.layer());

export const hashingLayer = defaultLayer(
  PasswordHashing,
  PasswordHashing.portableLayer().pipe(Layer.provide(admissionLayer)),
).pipe(Layer.provide(cryptoLayer));

export const newPasswordLayer = defaultLayer(NewPasswordCheck, NewPasswordCheck.layer());
