namespace Gma.Extensions.Organizations.Tenancy;

using Gma.Framework.AccessControl;
using Gma.Framework.Api.Tenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddOrganizationsTenancyExtension(
        this IServiceCollection services,
        Action<OrganizationsTenancyOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.AddOptions<OrganizationsTenancyOptions>()
            .Validate(
                options => options.BypassedSubjectKinds.All(kind =>
                    kind is AccessSubjectKind.AdminActor or AccessSubjectKind.Service or AccessSubjectKind.System),
                "Only admin actor, service, and system subjects can bypass organization membership checks.")
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<
            ITenantEndpointAccessPolicy,
            OrganizationTenantAccessPolicy>());

        return services;
    }
}
