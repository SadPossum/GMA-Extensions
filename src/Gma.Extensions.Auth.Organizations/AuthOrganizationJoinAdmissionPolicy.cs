namespace Gma.Extensions.Auth.Organizations;

using Gma.Modules.Auth.Contracts;
using Gma.Modules.Organizations.Contracts;
using Microsoft.Extensions.Options;

internal sealed class AuthOrganizationJoinAdmissionPolicy(
    IAuthMemberAdmissionReader admissions,
    IOptions<AuthOrganizationsOptions> options)
    : IOrganizationJoinAdmissionPolicy
{
    public async ValueTask<OrganizationJoinAdmissionDecision> EvaluateAsync(
        OrganizationJoinAdmissionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!Guid.TryParse(context.ApplicantSubjectId, out Guid memberId))
        {
            return OrganizationJoinAdmissionDecision.Denied;
        }

        AuthMemberAdmission? admission = await admissions.FindActiveAsync(
                options.Value.GlobalAuthScopeId,
                memberId,
                cancellationToken)
            .ConfigureAwait(false);
        return admission is null
            ? OrganizationJoinAdmissionDecision.Denied
            : OrganizationJoinAdmissionDecision.Allowed;
    }
}
