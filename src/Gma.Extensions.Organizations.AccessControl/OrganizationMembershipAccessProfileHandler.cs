namespace Gma.Extensions.Organizations.AccessControl;

using Gma.Framework.AccessControl;
using Gma.Framework.Messaging;
using Gma.Modules.AccessControl.Contracts;
using Gma.Modules.Organizations.Contracts;
using Microsoft.Extensions.Options;

internal sealed class OrganizationMembershipAccessProfileHandler(
    IAccessProfileAssignmentRevoker revoker,
    IOptions<OrganizationsAccessControlOptions> options)
    : IIntegrationEventHandler<OrganizationMembershipChangedIntegrationEvent>
{
    public async Task HandleAsync(
        OrganizationMembershipChangedIntegrationEvent integrationEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        if (integrationEvent.Status is not (
                OrganizationMembershipStatus.Suspended or OrganizationMembershipStatus.Removed))
        {
            return;
        }

        AccessScope ownerScope = AccessScope.Create(AccessScopeSegment.Create(
            options.Value.OwnerScopeSegmentName,
            integrationEvent.ScopeId));
        await revoker.RevokeAllAsync(
                AccessSubject.User(integrationEvent.SubjectId),
                ownerScope,
                AccessSubject.System(options.Value.SystemActorId),
                cancellationToken)
            .ConfigureAwait(false);
    }
}
