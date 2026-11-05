namespace Gma.Extensions.Auth.Notifications.Tests;

using Gma.Framework.Messaging;
using Gma.Framework.Modules;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Notifications.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthNotificationSubscriptionMetadataTests
{
    [Theory]
    [InlineData(typeof(MemberAuthenticatedIntegrationEvent), "auth-member-authenticated-notification")]
    [InlineData(typeof(MemberAuthenticationMethodChangedIntegrationEvent), "auth-method-changed-notification")]
    [InlineData(typeof(MemberPasswordRecoveryRequestedIntegrationEvent), "auth-password-recovery-request-notification")]
    [InlineData(typeof(MemberEmailVerificationRequestedIntegrationEvent), "auth-email-verification-request-notification")]
    [InlineData(typeof(MemberEmailVerifiedIntegrationEvent), "auth-email-verified-notification")]
    public void AuthBindingRetainsThePublishedScopeContractAndExistingDeliveryIdentity(Type eventType, string handlerName)
    {
        var services = new ServiceCollection();
        services.AddAuthNotificationsExtension();
        using ServiceProvider provider = services.BuildServiceProvider();
        IntegrationEventSubscription subscription = Assert.Single(provider
            .GetRequiredService<IIntegrationEventSubscriptionRegistry>().Subscriptions,
            candidate => candidate.EventType == eventType);

        Assert.True(subscription.Metadata.Contains<ScopeMetadataItem>());
        Assert.Equal(ModuleMetadataAttributeReader.Read(eventType), subscription.Metadata);
        Assert.Equal(NotificationsModuleMetadata.Name, subscription.ConsumerModule);
        Assert.Equal(AuthModuleMetadata.Name, subscription.ProducerModule);
        Assert.Equal(handlerName, subscription.HandlerName);
        Assert.Equal(IntegrationEventNameAttribute.GetRequired(eventType).EventName, subscription.EventName);
        Assert.Equal(IntegrationEventVersionAttribute.GetRequired(eventType).Version, subscription.Version);
        Assert.Equal(IntegrationEventNaming.CreateSubject(IntegrationEventNaming.DefaultSubjectPrefix,
            AuthModuleMetadata.Name, subscription.EventName, subscription.Version), subscription.Subject);
        Assert.True(IntegrationEventHandlerAttribute.GetRequired(subscription.HandlerType).RequiresExplicitProducerBinding);
    }

    [Fact]
    public void RepeatedCompositionRetainsExactlyFiveConsistentBindings()
    {
        var services = new ServiceCollection();
        services.AddAuthNotificationsExtension();
        services.AddAuthNotificationsExtension();
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Equal(5, provider.GetRequiredService<IIntegrationEventSubscriptionRegistry>().Subscriptions.Count);
    }
}
