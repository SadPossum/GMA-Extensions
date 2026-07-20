# Extensions

Extensions are optional integration packages, not modules. They live outside module repositories because a bridge necessarily knows about every module it connects.

## Auth + Notifications

`Gma.Extensions.Auth.Notifications` consumes Auth integration events and projects mandatory V2 security notifications for:

- new sign-ins;
- authentication-method changes;
- password-recovery requests, delivered only to the exact verified recovery address;
- email-verification requests;
- completed email verification.

It also supplies `IUserNotificationEmailAddressResolver`: recovery and verification messages use the exact address and expiry carried by the Auth event, fail terminally after expiry or on malformed payloads, and never fall back to another mailbox. Other alerts resolve the member's preferred verified email through `IAuthMemberContactReader` at delivery time. Recovery codes are never projected to the web channel. Hosts must encrypt and tightly retain every messaging, Notifications, and email-delivery record that temporarily carries a recovery code.

```csharp
using Gma.Extensions.Auth.Notifications;

builder.AddModule<NotificationsModule>();
builder.Services.AddAuthNotificationsExtension();
builder.Services.AddNotificationEmailAdapter(builder.Configuration);
```

The host must also register an `IEmailSender` and enable the email adapter before mail leaves the process.

## Auth + Organizations

`Gma.Extensions.Auth.Organizations` replaces Organizations' fail-closed recipient-invitation policy with an Auth-backed policy. Unbound invitations keep working without an Auth lookup. A recipient-bound invitation can be accepted only when the subject id is an Auth member id and that member owns the same preferred verified email in the configured global Auth scope.

```csharp
using Gma.Extensions.Auth.Organizations;

builder.AddAuthModule(AuthProfile.Global());
builder.AddModule<OrganizationsModule>();
builder.Services.AddAuthOrganizationsExtension();
```

Register the extension after the Organizations module. Pass a configuration callback when the application uses a non-default global Auth scope.

## Organizations + Tenancy

`Gma.Extensions.Organizations.Tenancy` plugs an Organizations access decision into the framework's tenant endpoint policy hook. Every endpoint using `RequireTenant()` then fails closed for user subjects unless the selected tenant is an active organization with an active membership. Admin actor, service, and system subjects bypass membership lookup by default; user bypasses are rejected by options validation.

```csharp
using Gma.Extensions.Organizations.Tenancy;

builder.AddModule<OrganizationsModule>();
builder.Services.AddOrganizationsTenancyExtension();
```

Register the extension after Organizations. It installs the default claims-based AccessControl subject resolver when the application has not supplied one; custom resolvers should be registered first. The module remains independent: Organizations references neither Tenancy nor this repository.

## Organizations + AccessControl

`Gma.Extensions.Organizations.AccessControl` consumes organization membership lifecycle events in AccessControl's durable inbox. Suspended and removed memberships lose every scoped access-profile assignment in that organization's exact owner scope. Active membership changes are ignored. Revocation is transactional and idempotent inside AccessControl, preserves immutable unassignment history, and does not remove compatibility roles or assignments in another scope.

```csharp
using Gma.Extensions.Organizations.AccessControl;

builder.AddModule<OrganizationsModule>();
builder.Services.AddAccessControlApplication(builder.Configuration);
builder.AddAccessControlPersistence();
builder.Services.AddOrganizationsAccessControlExtension(options =>
{
    options.OwnerScopeSegmentName = "tenant";
    options.SystemActorId = "organizations-membership-sync";
});
```

Compose the extension only when both modules are installed. Products remain responsible for compatibility-role synchronization and for any assignment-eligibility policy tied to product membership or employment state. The extension contains no role names, permission sets, invitation behavior, or product UI assumptions.

## Boundary rule

- Auth does not reference Notifications or this repository.
- Notifications does not reference Auth or this repository.
- Organizations does not reference Auth or this repository.
- Each extension references only the public contracts or explicit policy seams of the modules it composes.
- Product applications decide whether to mount and register the extension.
