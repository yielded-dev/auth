---
"@yielded/auth": minor
"@yielded/auth-persistence": minor
---

Enable phone account creation after SMS verification with `PhoneOtp.make({ allowSignUp: true })` through the ordinary `signIn` and `completeSignIn` methods, keeping explicit registration and number management independently opt-in with `lifecycle`. A `registration` lifecycle hook gates this signup and fails closed: a denied or unavailable hook sends no code and rejects completion like a wrong code.
