# GMA Extensions

Optional, reusable composition bridges for GMA applications.

GMA modules remain independently buildable and do not reference one another. An extension may intentionally reference the public seams of multiple modules to implement an opt-in product policy. Applications select only the extensions that match their installed modules.

Available extensions:

- `Gma.Extensions.Auth.Notifications` maps Auth security events into durable tagged Notifications requests and resolves Auth member email destinations at delivery time.

See `docs/README.md` for composition and boundary guidance.

