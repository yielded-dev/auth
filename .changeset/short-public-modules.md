---
"@yielded/auth": minor
---

Expose `Http` from the package root and shorten passkey and TOTP contract constructors.

BEHAVIOR CHANGE: Replace `makePasskeyContract`, `makePasskeyRegistrationContract`, and `makePasskeyManagementContract` with `PasskeyContract.make`, `.makeRegistration`, and `.makeManagement`; replace `makeTotpContract` with `TotpContract.make`.
