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
        var admissions = new StubAdmissions(
            new AuthMemberAdmission("person@example.com"));
        await using ServiceProvider provider = BuildProvider(admissions, "identity");
        IOrganizationInvitationRecipientVerificationPolicy policy = provider
            .GetRequiredService<IOrganizationInvitationRecipientVerificationPolicy>();

        OrganizationInvitationRecipientVerificationDecision decision =
            await policy.EvaluateAsync(
                Request(memberId.ToString("D"), "PERSON@example.com"),
                CancellationToken.None);

        Assert.Equal(
            OrganizationInvitationRecipientVerificationDecision.Verified,
            decision);
        Assert.Equal("identity", admissions.ScopeId);
        Assert.Equal(memberId, admissions.MemberId);
    }

    [Theory]
    [InlineData("another@example.com")]
    [InlineData(null)]
    public async Task Recipient_bound_invitation_fails_closed_without_matching_verified_email(string? verifiedEmail)
    {
        var admissions = new StubAdmissions(new AuthMemberAdmission(verifiedEmail));
        await using ServiceProvider provider = BuildProvider(admissions);
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
    public async Task Recipient_bound_invitation_rejects_an_inactive_member()
    {
        await using ServiceProvider provider = BuildProvider(new StubAdmissions(null));
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
    public async Task Active_member_can_create_and_join_an_organization_without_a_verified_email()
    {
        Guid memberId = Guid.NewGuid();
        var admissions = new StubAdmissions(new AuthMemberAdmission(null));
        await using ServiceProvider provider = BuildProvider(admissions, "identity");

        OrganizationCreationAdmissionDecision creation = await provider
            .GetRequiredService<IOrganizationCreationAdmissionPolicy>()
            .EvaluateAsync(CreationRequest(memberId.ToString("D")), CancellationToken.None);
        OrganizationJoinAdmissionDecision join = await provider
            .GetRequiredService<IOrganizationJoinAdmissionPolicy>()
            .EvaluateAsync(JoinContext(memberId.ToString("D")), CancellationToken.None);

        Assert.Equal(OrganizationCreationAdmissionDecision.Allowed, creation);
        Assert.Equal(OrganizationJoinAdmissionDecision.Allowed, join);
        Assert.Equal(2, admissions.CallCount);
        Assert.Equal("identity", admissions.ScopeId);
        Assert.Equal(memberId, admissions.MemberId);
    }

    [Fact]
    public async Task Inactive_member_cannot_create_or_join_an_organization()
    {
        await using ServiceProvider provider = BuildProvider(new StubAdmissions(null));
        string memberId = Guid.NewGuid().ToString("D");

        OrganizationCreationAdmissionDecision creation = await provider
            .GetRequiredService<IOrganizationCreationAdmissionPolicy>()
            .EvaluateAsync(CreationRequest(memberId), CancellationToken.None);
        OrganizationJoinAdmissionDecision join = await provider
            .GetRequiredService<IOrganizationJoinAdmissionPolicy>()
            .EvaluateAsync(JoinContext(memberId), CancellationToken.None);

        Assert.Equal(
            OrganizationCreationAdmissionDecision.SubjectVerificationRequired,
            creation);
        Assert.Equal(OrganizationJoinAdmissionDecision.Denied, join);
    }

    [Fact]
    public async Task Invalid_subject_does_not_query_auth()
    {
        var admissions = new StubAdmissions(
            new AuthMemberAdmission("person@example.com"));
        await using ServiceProvider provider = BuildProvider(admissions);
        IOrganizationInvitationRecipientVerificationPolicy policy = provider
            .GetRequiredService<IOrganizationInvitationRecipientVerificationPolicy>();

        OrganizationInvitationRecipientVerificationDecision decision =
            await policy.EvaluateAsync(
                Request("external-subject", "person@example.com"),
                CancellationToken.None);

        Assert.Equal(
            OrganizationInvitationRecipientVerificationDecision.NotVerified,
            decision);
        Assert.Null(admissions.ScopeId);
    }

    private static OrganizationCreationAdmissionRequest CreationRequest(string subjectId) =>
        new(
            Guid.NewGuid(),
            "Example organization",
            "example-organization",
            subjectId,
            subjectId);

    private static OrganizationJoinAdmissionContext JoinContext(string subjectId) =>
        new(
            OrganizationJoinAdmissionOperation.ClaimEnrollment,
            Guid.NewGuid(),
            Guid.NewGuid(),
            null,
            subjectId,
            subjectId,
            OrganizationEnrollmentApprovalMode.Automatic);

    private static OrganizationInvitationRecipientVerificationRequest Request(
        string subjectId,
        string recipientEmail) =>
        new(
            Guid.Parse("11111111-1111-4111-8111-111111111111"),
            Guid.Parse("22222222-2222-4222-8222-222222222222"),
            subjectId,
            recipientEmail);

    private static ServiceProvider BuildProvider(StubAdmissions admissions, string scopeId = AuthProfile.DefaultGlobalScopeId)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAuthMemberAdmissionReader>(admissions);
        services.AddAuthOrganizationsExtension(options => options.GlobalAuthScopeId = scopeId);
        return services.BuildServiceProvider();
    }

    private sealed class StubAdmissions(AuthMemberAdmission? admission)
        : IAuthMemberAdmissionReader
    {
        public int CallCount { get; private set; }
        public string? ScopeId { get; private set; }
        public Guid? MemberId { get; private set; }

        public ValueTask<AuthMemberAdmission?> FindActiveAsync(
            string scopeId,
            Guid memberId,
            CancellationToken cancellationToken = default)
        {
            this.CallCount++;
            this.ScopeId = scopeId;
            this.MemberId = memberId;
            return ValueTask.FromResult(admission);
        }
    }
}
