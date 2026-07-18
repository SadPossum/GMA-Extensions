namespace Gma.Extensions.Auth.Notifications.Tests;

using System.Text.Json;
using Gma.Framework.Notifications;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Notifications.Adapters.Email;
using Gma.Modules.Notifications.Application.Ports;
using Gma.Modules.Notifications.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ContractDeliveryPolicy = Gma.Modules.Notifications.Contracts.NotificationDeliveryPolicy;

[Trait("Category", "Unit")]
public sealed class AuthNotificationsExtensionTests
{
    [Fact]
    public async Task Password_recovery_delivery_resolves_the_exact_event_address()
    {
        using ServiceProvider services = new ServiceCollection().BuildServiceProvider();
        var resolver = new AuthUserNotificationEmailAddressResolver(services.GetRequiredService<IServiceScopeFactory>());
        UserNotificationMessage message = new(
            Guid.NewGuid(),
            AuthModuleMetadata.Name,
            "password-recovery-requested",
            1,
            "tenant-a",
            Guid.NewGuid().ToString("D"),
            "Reset your account password",
            "Use the recovery code.",
            Gma.Framework.Notifications.NotificationSeverity.Warning,
            DateTimeOffset.UtcNow,
            JsonSerializer.SerializeToElement(new { Email = "exact@example.com" }),
            deliveryPolicy: Gma.Framework.Notifications.NotificationDeliveryPolicy.Mandatory);

        NotificationEmailDestinationResult result = await resolver.ResolveAsync(message);

        Assert.Equal(NotificationEmailDestinationOutcome.Resolved, result.Outcome);
        Assert.Equal("exact@example.com", result.Address);
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
}
