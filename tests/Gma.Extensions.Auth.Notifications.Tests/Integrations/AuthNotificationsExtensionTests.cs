namespace Gma.Extensions.Auth.Notifications.Tests;

using System.Text.Json;
using Gma.Framework.Notifications;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Notifications.Adapters.Email;
using Gma.Modules.Notifications.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ContractDeliveryPolicy = Gma.Modules.Notifications.Contracts.NotificationDeliveryPolicy;
using FrameworkDeliveryPolicy = Gma.Framework.Notifications.NotificationDeliveryPolicy;
using FrameworkSeverity = Gma.Framework.Notifications.NotificationSeverity;

[Trait("Category", "Unit")]
public sealed class AuthNotificationsExtensionTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 20, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Password_recovery_destination_resolves_only_before_the_request_expires()
    {
        await using ServiceProvider provider = new ServiceCollection().BuildServiceProvider();
        AuthUserNotificationEmailAddressResolver resolver = new(
            provider.GetRequiredService<IServiceScopeFactory>(),
            new FixedClock());

        NotificationEmailDestinationResult current = await resolver.ResolveAsync(
            CreatePasswordRecoveryMessage(Now.AddMinutes(1)));
        NotificationEmailDestinationResult expired = await resolver.ResolveAsync(
            CreatePasswordRecoveryMessage(Now));

        Assert.Equal(NotificationEmailDestinationOutcome.Resolved, current.Outcome);
        Assert.Equal("exact@example.com", current.Address);
        Assert.Equal(NotificationEmailDestinationOutcome.Unavailable, expired.Outcome);
        Assert.Equal("auth-password-recovery-expired", expired.Code);
    }

    [Fact]
    public async Task Password_recovery_request_is_mandatory_email_only_and_keeps_the_exact_destination()
    {
        var projector = new CapturingProjector();
        var handler = new MemberPasswordRecoveryRequestedNotificationHandler(projector);
        Guid challengeId = Guid.NewGuid();
        var integrationEvent = new MemberPasswordRecoveryRequestedIntegrationEvent(
            Guid.NewGuid(),
            "tenant-a",
            DateTimeOffset.UtcNow,
            challengeId,
            Guid.NewGuid(),
            "owner@example.com",
            "one-time-recovery-code",
            DateTimeOffset.UtcNow.AddMinutes(30));

        await handler.HandleAsync(integrationEvent, CancellationToken.None);

        UserNotificationRequestedIntegrationEventV2 projected = Assert.IsType<UserNotificationRequestedIntegrationEventV2>(projector.Event);
        Assert.Equal(ContractDeliveryPolicy.Mandatory, projected.DeliveryPolicy);
        Assert.Contains(projected.Tags, tag => tag.Key == NotificationTags.Email);
        Assert.DoesNotContain(projected.Tags, tag => tag.Key == NotificationTags.Web);
        Assert.Contains(projected.Tags, tag => tag.Key == "domain:password-recovery");
        Assert.Contains("one-time-recovery-code", projected.Body, StringComparison.Ordinal);
        using JsonDocument payload = JsonDocument.Parse(projected.PayloadJson);
        Assert.Equal("owner@example.com", payload.RootElement.GetProperty("Email").GetString());
        Assert.Equal(challengeId, payload.RootElement.GetProperty("ChallengeId").GetGuid());
        Assert.Equal(integrationEvent.ExpiresAtUtc, payload.RootElement.GetProperty("ExpiresAtUtc").GetDateTimeOffset());
    }

    [Fact]
    public async Task Verification_request_is_mandatory_email_only_and_keeps_the_destination()
    {
        var projector = new CapturingProjector();
        var handler = new MemberEmailVerificationRequestedNotificationHandler(projector);
        var integrationEvent = new MemberEmailVerificationRequestedIntegrationEvent(
            Guid.NewGuid(),
            "tenant-a",
            DateTimeOffset.UtcNow,
            Guid.NewGuid(),
            "pending@example.com",
            "one-time-code",
            DateTimeOffset.UtcNow.AddHours(1));

        await handler.HandleAsync(integrationEvent, CancellationToken.None);

        UserNotificationRequestedIntegrationEventV2 projected = Assert.IsType<UserNotificationRequestedIntegrationEventV2>(projector.Event);
        Assert.Equal(ContractDeliveryPolicy.Mandatory, projected.DeliveryPolicy);
        Assert.Contains(projected.Tags, tag => tag.Key == NotificationTags.Email);
        Assert.DoesNotContain(projected.Tags, tag => tag.Key == NotificationTags.Web);
        using JsonDocument payload = JsonDocument.Parse(projected.PayloadJson);
        Assert.Equal("pending@example.com", payload.RootElement.GetProperty("Email").GetString());
        Assert.Equal(integrationEvent.ExpiresAtUtc, payload.RootElement.GetProperty("ExpiresAtUtc").GetDateTimeOffset());
    }

    [Fact]
    public async Task Verification_destination_resolves_only_before_the_request_expires()
    {
        await using ServiceProvider provider = new ServiceCollection().BuildServiceProvider();
        AuthUserNotificationEmailAddressResolver resolver = new(
            provider.GetRequiredService<IServiceScopeFactory>(),
            new FixedClock());

        NotificationEmailDestinationResult current = await resolver.ResolveAsync(
            CreateVerificationMessage(Now.AddMinutes(1)),
            CancellationToken.None);
        NotificationEmailDestinationResult expired = await resolver.ResolveAsync(
            CreateVerificationMessage(Now),
            CancellationToken.None);

        Assert.Equal(NotificationEmailDestinationOutcome.Resolved, current.Outcome);
        Assert.Equal("pending@example.com", current.Address);
        Assert.Equal(NotificationEmailDestinationOutcome.Unavailable, expired.Outcome);
        Assert.Equal("auth-email-verification-expired", expired.Code);
    }

    [Fact]
    public async Task Malformed_verification_payload_does_not_fall_back_to_member_contact()
    {
        await using ServiceProvider provider = new ServiceCollection().BuildServiceProvider();
        AuthUserNotificationEmailAddressResolver resolver = new(
            provider.GetRequiredService<IServiceScopeFactory>(),
            new FixedClock());
        UserNotificationMessage message = CreateMessage(JsonSerializer.SerializeToElement(new
        {
            Email = "pending@example.com",
        }));

        NotificationEmailDestinationResult result = await resolver.ResolveAsync(message, CancellationToken.None);

        Assert.Equal(NotificationEmailDestinationOutcome.Unavailable, result.Outcome);
        Assert.Equal("auth-email-verification-payload-invalid", result.Code);
    }

    [Fact]
    public async Task Sign_in_alert_routes_to_web_and_email_with_security_context()
    {
        var projector = new CapturingProjector();
        var handler = new MemberAuthenticatedNotificationHandler(projector);
        var integrationEvent = new MemberAuthenticatedIntegrationEvent(
            Guid.NewGuid(),
            "tenant-a",
            DateTimeOffset.UtcNow,
            Guid.NewGuid(),
            Guid.NewGuid(),
            "external:google",
            "203.0.113.10",
            "test-agent");

        await handler.HandleAsync(integrationEvent, CancellationToken.None);

        UserNotificationRequestedIntegrationEventV2 projected = Assert.IsType<UserNotificationRequestedIntegrationEventV2>(projector.Event);
        Assert.Equal(ContractDeliveryPolicy.Mandatory, projected.DeliveryPolicy);
        Assert.Contains(projected.Tags, tag => tag.Key == NotificationTags.Email);
        Assert.Contains(projected.Tags, tag => tag.Key == NotificationTags.Web);
        Assert.Contains(projected.Tags, tag => tag.Key == "domain:security");
        Assert.Contains("203.0.113.10", projected.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Authentication_method_change_is_a_mandatory_security_alert()
    {
        var projector = new CapturingProjector();
        var handler = new MemberAuthenticationMethodChangedNotificationHandler(projector);
        var integrationEvent = new MemberAuthenticationMethodChangedIntegrationEvent(
            Guid.NewGuid(),
            "tenant-a",
            DateTimeOffset.UtcNow,
            Guid.NewGuid(),
            "external:google",
            AuthenticationMethodChange.Added);

        await handler.HandleAsync(integrationEvent, CancellationToken.None);

        UserNotificationRequestedIntegrationEventV2 projected = Assert.IsType<UserNotificationRequestedIntegrationEventV2>(projector.Event);
        Assert.Equal(ContractDeliveryPolicy.Mandatory, projected.DeliveryPolicy);
        Assert.Contains(projected.Tags, tag => tag.Key == NotificationTags.Email);
        Assert.Contains(projected.Tags, tag => tag.Key == NotificationTags.Web);
        Assert.Contains("external:google", projected.Body, StringComparison.Ordinal);
    }

    private sealed class CapturingProjector : IUserNotificationRequestProjector
    {
        public UserNotificationRequestedIntegrationEventV2? Event { get; private set; }

        public Task ProjectAsync(
            UserNotificationRequestedIntegrationEventV2 integrationEvent,
            CancellationToken cancellationToken)
        {
            this.Event = integrationEvent;
            return Task.CompletedTask;
        }
    }
    private static UserNotificationMessage CreateVerificationMessage(DateTimeOffset expiresAtUtc) =>
        CreateExactAddressMessage(
            "email-verification-requested",
            "pending@example.com",
            expiresAtUtc,
            FrameworkSeverity.Info);

    private static UserNotificationMessage CreatePasswordRecoveryMessage(DateTimeOffset expiresAtUtc) =>
        CreateExactAddressMessage(
            "password-recovery-requested",
            "exact@example.com",
            expiresAtUtc,
            FrameworkSeverity.Warning);

    private static UserNotificationMessage CreateMessage(JsonElement payload) =>
        CreateMessage("email-verification-requested", FrameworkSeverity.Info, payload);

    private static UserNotificationMessage CreateExactAddressMessage(
        string name,
        string email,
        DateTimeOffset expiresAtUtc,
        FrameworkSeverity severity) =>
        CreateMessage(name, severity, JsonSerializer.SerializeToElement(new
        {
            Email = email,
            ExpiresAtUtc = expiresAtUtc,
        }));

    private static UserNotificationMessage CreateMessage(
        string name,
        FrameworkSeverity severity,
        JsonElement payload) =>
        new(
            Guid.CreateVersion7(),
            AuthModuleMetadata.Name,
            name,
            1,
            "tenant-a",
            Guid.CreateVersion7().ToString("D"),
            name,
            null,
            severity,
            Now,
            payload,
            [NotificationTags.Email],
            FrameworkDeliveryPolicy.Mandatory);

    private sealed class FixedClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
    }
}
