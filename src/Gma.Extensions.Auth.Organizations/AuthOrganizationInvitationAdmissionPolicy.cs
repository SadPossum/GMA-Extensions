namespace Gma.Extensions.Auth.Organizations;

using Gma.Framework.Results;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Organizations.Application;
using Gma.Modules.Organizations.Application.Ports;
using Microsoft.Extensions.Options;

internal sealed class AuthOrganizationInvitationAdmissionPolicy(
    IAuthMemberContactReader contacts,
    IOptions<AuthOrganizationsOptions> options) : IOrganizationInvitationAdmissionPolicy
{
    public async Task<Result> CanAcceptInvitationAsync(
        string subjectId,
        string? recipientEmail,
        CancellationToken cancellationToken)
    {
        if (recipientEmail is null)
        {
            return Result.Success();
        }

        if (!Guid.TryParse(subjectId, out Guid memberId))
        {
            return Result.Failure(OrganizationApplicationErrors.RecipientVerificationRequired);
        }

        string? verifiedEmail = await contacts.GetPreferredVerifiedEmailAsync(
            options.Value.GlobalAuthScopeId,
            memberId,
            cancellationToken).ConfigureAwait(false);

        return string.Equals(verifiedEmail?.Trim(), recipientEmail.Trim(), StringComparison.OrdinalIgnoreCase)
            ? Result.Success()
            : Result.Failure(OrganizationApplicationErrors.RecipientVerificationRequired);
    }
}
