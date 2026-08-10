namespace Gma.Extensions.Auth.Organizations.Tests;

using Gma.Modules.Auth.Contracts;
using Gma.Modules.Organizations.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthOrganizationsExtensionTests
{
    [Fact]
    public async Task Recipient_bound_invitation_requires_the_same_verified_email()
    {
        Guid memberId = Guid.NewGuid();
        var contacts = new StubContacts("person@example.com");
        await using ServiceProvider provider = BuildProvider(contacts, "identity");
        IOrganizationInvitationRecipientVerificationPolicy policy = provider
            .GetRequiredService<IOrganizationInvitationRecipientVerificationPolicy>();

        OrganizationInvitationRecipientVerificationDecision decision =
            await policy.EvaluateAsync(
                Request(memberId.ToString("D"), "PERSON@example.com"),
                CancellationToken.None);

        Assert.Equal(
            OrganizationInvitationRecipientVerificationDecision.Verified,
            decision);
        Assert.Equal("identity", contacts.ScopeId);
        Assert.Equal(memberId, contacts.MemberId);
    }

    [Theory]
    [InlineData("another@example.com")]
    [InlineData(null)]
    public async Task Recipient_bound_invitation_fails_closed_without_matching_verified_email(string? verifiedEmail)
    {
        var contacts = new StubContacts(verifiedEmail);
        await using ServiceProvider provider = BuildProvider(contacts);
        IOrganizationInvitationRecipientVerificationPolicy policy = provider
            .GetRequiredService<IOrganizationInvitationRecipientVerificationPolicy>();

        OrganizationInvitationRecipientVerificationDecision decision =
            await policy.EvaluateAsync(
                Request(Guid.NewGuid().ToString("D"), "person@example.com"),
                CancellationToken.None);

        Assert.Equal(
            OrganizationInvitationRecipientVerificationDecision.NotVerified,
            decision);
    }

    [Fact]
    public async Task Invalid_subject_does_not_query_auth()
    {
        var contacts = new StubContacts("person@example.com");
        await using ServiceProvider provider = BuildProvider(contacts);
        IOrganizationInvitationRecipientVerificationPolicy policy = provider
            .GetRequiredService<IOrganizationInvitationRecipientVerificationPolicy>();

        OrganizationInvitationRecipientVerificationDecision decision =
            await policy.EvaluateAsync(
                Request("external-subject", "person@example.com"),
                CancellationToken.None);

        Assert.Equal(
            OrganizationInvitationRecipientVerificationDecision.NotVerified,
            decision);
        Assert.Null(contacts.ScopeId);
    }

    private static OrganizationInvitationRecipientVerificationRequest Request(
        string subjectId,
        string recipientEmail) =>
        new(
            Guid.Parse("11111111-1111-4111-8111-111111111111"),
            Guid.Parse("22222222-2222-4222-8222-222222222222"),
            subjectId,
            recipientEmail);

    private static ServiceProvider BuildProvider(StubContacts contacts, string scopeId = AuthProfile.DefaultGlobalScopeId)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAuthMemberContactReader>(contacts);
        services.AddAuthOrganizationsExtension(options => options.GlobalAuthScopeId = scopeId);
        return services.BuildServiceProvider();
    }

    private sealed class StubContacts(string? verifiedEmail) : IAuthMemberContactReader
    {
        public string? ScopeId { get; private set; }
        public Guid? MemberId { get; private set; }

        public ValueTask<string?> GetPreferredVerifiedEmailAsync(
            string scopeId,
            Guid memberId,
            CancellationToken cancellationToken = default)
        {
            this.ScopeId = scopeId;
            this.MemberId = memberId;
            return ValueTask.FromResult(verifiedEmail);
        }
    }
}
