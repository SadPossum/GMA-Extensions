namespace Gma.Extensions.Auth.Organizations.Tests;

using Gma.Modules.Auth.Contracts;
using Gma.Modules.Organizations.Application;
using Gma.Modules.Organizations.Application.Ports;
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
        IOrganizationInvitationAdmissionPolicy policy = provider.GetRequiredService<IOrganizationInvitationAdmissionPolicy>();

        var accepted = await policy.CanAcceptInvitationAsync(
            memberId.ToString("D"),
            "PERSON@example.com",
            CancellationToken.None);

        Assert.True(accepted.IsSuccess);
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
        IOrganizationInvitationAdmissionPolicy policy = provider.GetRequiredService<IOrganizationInvitationAdmissionPolicy>();

        var accepted = await policy.CanAcceptInvitationAsync(
            Guid.NewGuid().ToString("D"),
            "person@example.com",
            CancellationToken.None);

        Assert.False(accepted.IsSuccess);
        Assert.Equal(OrganizationApplicationErrors.RecipientVerificationRequired.Code, accepted.Error.Code);
    }

    [Fact]
    public async Task Unbound_invitation_does_not_query_auth()
    {
        var contacts = new StubContacts("person@example.com");
        await using ServiceProvider provider = BuildProvider(contacts);
        IOrganizationInvitationAdmissionPolicy policy = provider.GetRequiredService<IOrganizationInvitationAdmissionPolicy>();

        var accepted = await policy.CanAcceptInvitationAsync(
            "external-subject",
            recipientEmail: null,
            CancellationToken.None);

        Assert.True(accepted.IsSuccess);
        Assert.Null(contacts.ScopeId);
    }

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
