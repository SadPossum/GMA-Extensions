namespace Gma.Extensions.Organizations.Tenancy;

using Gma.Framework.AccessControl;
using Gma.Framework.AccessControl.AspNetCore;
using Gma.Framework.Api.Tenancy;
using Gma.Modules.Organizations.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

internal sealed partial class OrganizationTenantAccessPolicy(
    IAccessHttpSubjectResolver subjectResolver,
    IOrganizationAccessDecisionReader accessReader,
    IOptions<OrganizationsTenancyOptions> options,
    ILogger<OrganizationTenantAccessPolicy>? logger = null) : ITenantEndpointAccessPolicy
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

        OrganizationAccessDecision decision;
        try
        {
            decision = await accessReader
                .ReadAsync(organizationId, subject.Id, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            if (logger is not null)
            {
                LogReaderFailure(
                    logger,
                    accessReader.GetType().FullName,
                    exception.GetType().Name);
            }

            return AccessUnavailable();
        }

        return decision switch
        {
            OrganizationAccessDecision.Allowed => TenantEndpointAccessDecision.Allowed,
            OrganizationAccessDecision.OrganizationNotFound or
                OrganizationAccessDecision.OrganizationInactive or
                OrganizationAccessDecision.MembershipNotFound or
                OrganizationAccessDecision.MembershipInactive => AccessDenied(),
            _ => this.IndeterminateAccess()
        };
    }

    private TenantEndpointAccessDecision IndeterminateAccess()
    {
        if (logger is not null)
        {
            LogIndeterminateDecision(logger, accessReader.GetType().FullName);
        }

        return AccessUnavailable();
    }

    private static TenantEndpointAccessDecision AccessDenied() =>
        TenantEndpointAccessDecision.Denied(
            OrganizationTenancyErrors.AccessDeniedCode,
            OrganizationTenancyErrors.AccessDeniedMessage);

    private static TenantEndpointAccessDecision AccessUnavailable() =>
        TenantEndpointAccessDecision.Denied(
            OrganizationTenancyErrors.AccessUnavailableCode,
            OrganizationTenancyErrors.AccessUnavailableMessage,
            StatusCodes.Status503ServiceUnavailable);

    [LoggerMessage(
        EventId = 4201,
        Level = LogLevel.Error,
        Message = "Organization access reader {ReaderType} failed with {ExceptionType}; tenant access is unavailable.")]
    private static partial void LogReaderFailure(
        ILogger logger,
        string? readerType,
        string exceptionType);

    [LoggerMessage(
        EventId = 4202,
        Level = LogLevel.Warning,
        Message = "Organization access reader {ReaderType} returned an indeterminate decision; tenant access is unavailable.")]
    private static partial void LogIndeterminateDecision(
        ILogger logger,
        string? readerType);
}
