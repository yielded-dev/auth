---
"@yielded/auth": patch
---

Accept the `scope`, `authuser`, `prompt` and `hd` query parameters that Google appends to its OAuth callback. Google sign-in previously failed with a `TransportFailure` unless the application listed them in `allowedQueryParameters`. Providers declare such parameters with `callbackQueryParameters`, and the OAuth proxy now also accepts `hd`.
