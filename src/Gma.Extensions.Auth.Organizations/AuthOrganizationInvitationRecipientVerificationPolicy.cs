namespace Gma.Extensions.Auth.Organizations;

using Gma.Modules.Auth.Contracts;
using Gma.Modules.Organizations.Contracts;
using Microsoft.Extensions.Options;

internal sealed class AuthOrganizationInvitationRecipientVerificationPolicy(
    IAuthMemberAdmissionReader admissions,
    IOptions<AuthOrganizationsOptions> options)
    : IOrganizationInvitationRecipientVerificationPolicy
{
    public async ValueTask<OrganizationInvitationRecipientVerificationDecision> EvaluateAsync(
        OrganizationInvitationRecipientVerificationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!Guid.TryParse(request.SubjectId, out Guid memberId))
        {
            return OrganizationInvitationRecipientVerificationDecision.NotVerified;
        }

        AuthMemberAdmission? admission = await admissions.FindActiveAsync(
                options.Value.GlobalAuthScopeId,
                memberId,
                cancellationToken)
            .ConfigureAwait(false);

        return string.Equals(
                admission?.PreferredVerifiedEmail?.Trim(),
                request.RecipientEmail.Trim(),
                StringComparison.OrdinalIgnoreCase)
            ? OrganizationInvitationRecipientVerificationDecision.Verified
            : OrganizationInvitationRecipientVerificationDecision.NotVerified;
    }
}
