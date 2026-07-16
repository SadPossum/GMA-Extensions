namespace Gma.Extensions.Organizations.Tenancy;

using Gma.Framework.AccessControl;
using Gma.Framework.AccessControl.AspNetCore;
using Gma.Framework.Api.Tenancy;
using Gma.Modules.Organizations.Application.Ports;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

internal sealed class OrganizationTenantAccessPolicy(
    IAccessHttpSubjectResolver subjectResolver,
    IOrganizationAccessDecisionReader accessReader,
    IOptions<OrganizationsTenancyOptions> options) : ITenantEndpointAccessPolicy
{
    public async ValueTask<TenantEndpointAccessDecision> AuthorizeAsync(
        HttpContext httpContext,
        string tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        AccessSubject? subject = subjectResolver.ResolveSubject(httpContext);
        if (subject is null)
        {
            return TenantEndpointAccessDecision.Denied(
                OrganizationTenancyErrors.UnauthenticatedCode,
                OrganizationTenancyErrors.UnauthenticatedMessage,
                StatusCodes.Status401Unauthorized);
        }

        if (options.Value.BypassedSubjectKinds.Contains(subject.Kind))
        {
            return TenantEndpointAccessDecision.Allowed;
        }

        if (subject.Kind != AccessSubjectKind.User ||
            !Guid.TryParse(tenantId, out Guid organizationId) ||
            organizationId == Guid.Empty)
        {
            return AccessDenied();
        }

        OrganizationAccessDecision decision = await accessReader
            .ReadAsync(organizationId, subject.Id, cancellationToken)
            .ConfigureAwait(false);
        return decision == OrganizationAccessDecision.Allowed
            ? TenantEndpointAccessDecision.Allowed
            : AccessDenied();
    }

    private static TenantEndpointAccessDecision AccessDenied() =>
        TenantEndpointAccessDecision.Denied(
            OrganizationTenancyErrors.AccessDeniedCode,
            OrganizationTenancyErrors.AccessDeniedMessage);
}
