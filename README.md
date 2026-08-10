# GMA Extensions

Optional, reusable composition bridges for GMA applications.

GMA modules remain independently buildable and do not reference one another. An extension may intentionally reference the public seams of multiple modules to implement an opt-in product policy. Applications select only the extensions that match their installed modules.

Available extensions:

- `Gma.Extensions.Auth.Notifications` maps Auth security events into durable tagged Notifications requests and resolves active Auth member email destinations for other modules at delivery time.
- `Gma.Extensions.Auth.Organizations` requires active Auth members for organization creation/join and verifies recipient-bound invitations against the accepting member's preferred verified email.
- `Gma.Extensions.Organizations.AccessControl` revokes scoped access-profile assignments when an organization membership is suspended or removed.
- `Gma.Extensions.Organizations.Tenancy` denies tenant-scoped HTTP requests when the selected organization or user membership is inactive, reports unavailable authority as HTTP 503, and explicitly bypasses admin, service, and system subjects.

See `docs/README.md` for composition and boundary guidance.
