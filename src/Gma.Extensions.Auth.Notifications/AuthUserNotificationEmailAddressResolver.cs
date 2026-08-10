namespace Gma.Extensions.Auth.Notifications;

using Gma.Framework.Email;
using Gma.Framework.Notifications;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Notifications.Adapters.Email;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

internal sealed class AuthUserNotificationEmailAddressResolver(
    IServiceScopeFactory scopeFactory,
    ISystemClock clock,
    IOptions<AuthNotificationsOptions> options)
    : IUserNotificationEmailAddressResolver
{
    public async ValueTask<NotificationEmailDestinationResult> ResolveAsync(
        UserNotificationMessage message,
        CancellationToken cancellationToken = default)
    {
        if (IsExactAddressRequest(message))
        {
            return ResolveExactAddressDestination(message, clock.UtcNow);
        }

        if (!Guid.TryParse(message.UserId, out Guid memberId))
        {
            return NotificationEmailDestinationResult.Unavailable("auth-member-id-invalid");
        }

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        string? email;
        if (string.Equals(message.Module, AuthModuleMetadata.Name, StringComparison.Ordinal))
        {
            IAuthMemberContactReader reader = scope.ServiceProvider
                .GetRequiredService<IAuthMemberContactReader>();
            email = await reader
                .GetPreferredVerifiedEmailAsync(message.ScopeId, memberId, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            IAuthMemberAdmissionReader reader = scope.ServiceProvider
                .GetRequiredService<IAuthMemberAdmissionReader>();
            string authScopeId = options.Value.FixedAuthScopeId ?? message.ScopeId;
            AuthMemberAdmission? admission = await reader
                .FindActiveAsync(authScopeId, memberId, cancellationToken)
                .ConfigureAwait(false);
            email = admission?.PreferredVerifiedEmail;
        }

        return EmailSendRequest.IsValidAddress(email)
            ? NotificationEmailDestinationResult.Resolved(email!)
            : NotificationEmailDestinationResult.Unavailable("auth-verified-email-unavailable");
    }

    private static bool IsExactAddressRequest(UserNotificationMessage message) =>
        string.Equals(message.Module, AuthModuleMetadata.Name, StringComparison.Ordinal) &&
        (string.Equals(message.Name, "email-verification-requested", StringComparison.Ordinal) ||
         string.Equals(message.Name, "password-recovery-requested", StringComparison.Ordinal));

    private static NotificationEmailDestinationResult ResolveExactAddressDestination(
        UserNotificationMessage message,
        DateTimeOffset nowUtc)
    {
        string codePrefix = string.Equals(
            message.Name,
            "password-recovery-requested",
            StringComparison.Ordinal)
            ? "auth-password-recovery"
            : "auth-email-verification";
        if (message.Payload.ValueKind != System.Text.Json.JsonValueKind.Object ||
            !message.Payload.TryGetProperty("Email", out System.Text.Json.JsonElement emailProperty) ||
            !message.Payload.TryGetProperty("ExpiresAtUtc", out System.Text.Json.JsonElement expiryProperty) ||
            !expiryProperty.TryGetDateTimeOffset(out DateTimeOffset expiresAtUtc))
        {
            return NotificationEmailDestinationResult.Unavailable($"{codePrefix}-payload-invalid");
        }

        string? email = emailProperty.GetString();
        if (!EmailSendRequest.IsValidAddress(email))
        {
            return NotificationEmailDestinationResult.Unavailable($"{codePrefix}-payload-invalid");
        }

        return expiresAtUtc <= nowUtc
            ? NotificationEmailDestinationResult.Unavailable($"{codePrefix}-expired")
            : NotificationEmailDestinationResult.Resolved(email!);
    }
}
