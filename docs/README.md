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

## Boundary rule

- Auth does not reference Notifications or this repository.
- Notifications does not reference Auth or this repository.
- This extension references only the public Auth and Notifications seams it composes.
- Product applications decide whether to mount and register the extension.

