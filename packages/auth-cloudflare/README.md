# @yielded/auth-cloudflare

Cloudflare Durable Object storage and email delivery for Yielded Auth through
`effect-cf`. The application owns Worker bindings, telemetry, sender domains,
and deployment configuration.

`layerAuthStore` supplies core's `AuthStore`; `layerEmailOtpSender` supplies
`EmailOtpSender`. Email delivery uses the Worker's `waitUntil` lifetime, so an
accepted request does not establish successful delivery.
