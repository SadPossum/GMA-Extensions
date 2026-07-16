# Extensions

Extensions are optional integration packages, not modules. They live outside module repositories because a bridge necessarily knows about every module it connects.

## Auth + Notifications

`Gma.Extensions.Auth.Notifications` consumes Auth integration events and projects mandatory V2 security notifications for:

- new sign-ins;
- authentication-method changes;
- email-verification requests;
- completed email verification.

It also supplies `IUserNotificationEmailAddressResolver`: verification messages use the pending address carried by the Auth event, while other alerts resolve the member's preferred verified email through `IAuthMemberContactReader` at delivery time.

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

## Boundary rule

- Auth does not reference Notifications or this repository.
- Notifications does not reference Auth or this repository.
- Organizations does not reference Auth or this repository.
- This extension references only the public Auth and Notifications seams it composes.
- Product applications decide whether to mount and register the extension.
