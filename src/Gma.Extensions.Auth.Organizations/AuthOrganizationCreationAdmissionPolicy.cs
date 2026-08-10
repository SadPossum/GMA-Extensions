namespace Gma.Extensions.Auth.Organizations;

using Gma.Modules.Auth.Contracts;
using Gma.Modules.Organizations.Contracts;
using Microsoft.Extensions.Options;

internal sealed class AuthOrganizationCreationAdmissionPolicy(
    IAuthMemberAdmissionReader admissions,
    IOptions<AuthOrganizationsOptions> options)
    : IOrganizationCreationAdmissionPolicy
{
    public async ValueTask<OrganizationCreationAdmissionDecision> EvaluateAsync(
        OrganizationCreationAdmissionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!Guid.TryParse(request.SubjectId, out Guid memberId))
        {
            return OrganizationCreationAdmissionDecision.SubjectVerificationRequired;
        }

        AuthMemberAdmission? admission = await admissions.FindActiveAsync(
                options.Value.GlobalAuthScopeId,
                memberId,
                cancellationToken)
            .ConfigureAwait(false);
        return admission is null
            ? OrganizationCreationAdmissionDecision.SubjectVerificationRequired
            : OrganizationCreationAdmissionDecision.Allowed;
    }
}
