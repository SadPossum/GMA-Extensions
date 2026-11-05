namespace Gma.Extensions.Auth.Notifications;

using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Notifications.Adapters.Email;
using Gma.Modules.Notifications.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthNotificationsExtension(
        this IServiceCollection services,
        Action<AuthNotificationsOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configure is not null)
        {
            services.Configure(configure);
        }
        else
        {
            services.AddOptions<AuthNotificationsOptions>();
        }

        services.AddOptions<AuthNotificationsOptions>()
            .Validate(
                options => options.FixedAuthScopeId is null ||
                    !string.IsNullOrWhiteSpace(options.FixedAuthScopeId),
                "A fixed Auth scope id cannot be empty.")
            .ValidateOnStart();
        services.TryAddSingleton<IUserNotificationEmailAddressResolver, AuthUserNotificationEmailAddressResolver>();
        services.AddIntegrationEventHandler<
            MemberAuthenticatedIntegrationEvent,
            MemberAuthenticatedNotificationHandler>(
            NotificationsModuleMetadata.Name,
            AuthModuleMetadata.Name);
        services.AddIntegrationEventHandler<
            MemberAuthenticationMethodChangedIntegrationEvent,
            MemberAuthenticationMethodChangedNotificationHandler>(
            NotificationsModuleMetadata.Name,
            AuthModuleMetadata.Name);
        services.AddIntegrationEventHandler<
            MemberPasswordRecoveryRequestedIntegrationEvent,
            MemberPasswordRecoveryRequestedNotificationHandler>(
            NotificationsModuleMetadata.Name,
            AuthModuleMetadata.Name);
        services.AddIntegrationEventHandler<
            MemberEmailVerificationRequestedIntegrationEvent,
            MemberEmailVerificationRequestedNotificationHandler>(
            NotificationsModuleMetadata.Name,
            AuthModuleMetadata.Name);
        services.AddIntegrationEventHandler<
            MemberEmailVerifiedIntegrationEvent,
            MemberEmailVerifiedNotificationHandler>(
            NotificationsModuleMetadata.Name,
            AuthModuleMetadata.Name);

        return services;
    }
}
