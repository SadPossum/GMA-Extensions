namespace Gma.Extensions.Auth.Organizations;

using Gma.Modules.Organizations.Application.Ports;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthOrganizationsExtension(
        this IServiceCollection services,
        Action<AuthOrganizationsOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configure is not null)
        {
            services.Configure(configure);
        }
        else
        {
            services.AddOptions<AuthOrganizationsOptions>();
        }

        services.AddOptions<AuthOrganizationsOptions>()
            .Validate(
                options => !string.IsNullOrWhiteSpace(options.GlobalAuthScopeId),
                "A global Auth scope id is required.")
            .ValidateOnStart();
        services.Replace(ServiceDescriptor.Scoped<
            IOrganizationInvitationAdmissionPolicy,
            AuthOrganizationInvitationAdmissionPolicy>());

        return services;
    }
}
