namespace Gma.Extensions.Organizations.AccessControl;

using Gma.Framework.AccessControl;
using Gma.Framework.Messaging;
using Gma.Modules.AccessControl.Contracts;
using Gma.Modules.Organizations.Contracts;
using Microsoft.Extensions.DependencyInjection;

public static class DependencyInjection
{
    public static IServiceCollection AddOrganizationsAccessControlExtension(
        this IServiceCollection services,
        Action<OrganizationsAccessControlOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.AddOptions<OrganizationsAccessControlOptions>()
            .Validate(
                options => AccessScopeSegment.TryCreate(
                    options.OwnerScopeSegmentName,
                    "validation",
                    out _),
                "The organization access-control owner-scope segment name is invalid.")
            .Validate(
                options => AccessSubject.TryCreate(
                    AccessSubjectKind.System,
                    options.SystemActorId,
                    out _),
                "The organization access-control system actor id is invalid.")
            .ValidateOnStart();
        services.AddIntegrationEventHandler<
            OrganizationMembershipChangedIntegrationEvent,
            OrganizationMembershipAccessProfileHandler>(
            AccessControlModuleMetadata.Name,
            OrganizationsModuleMetadata.Name,
            OrganizationMembershipChangedIntegrationEvent.EventType,
            OrganizationMembershipChangedIntegrationEvent.EventVersion,
            "organizations-membership-access-profile-revocation");
        return services;
    }
}
