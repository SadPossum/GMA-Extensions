namespace Gma.Extensions.Organizations.Tenancy.Tests;

using Gma.Extensions.Organizations.Tenancy;
using Gma.Framework.AccessControl;
using Gma.Framework.AccessControl.AspNetCore;
using Gma.Framework.Api.Tenancy;
using Gma.Modules.Organizations.Application.Ports;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

[Trait("Category", "Unit")]
public sealed class OrganizationTenantAccessPolicyTests
{
    [Fact]
    public async Task Active_user_membership_is_allowed()
    {
        Guid organizationId = Guid.NewGuid();
        RecordingAccessReader reader = new(OrganizationAccessDecision.Allowed);
        ITenantEndpointAccessPolicy policy = CreatePolicy(AccessSubject.User("member-a"), reader);

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(), organizationId.ToString("D"), CancellationToken.None);

        Assert.True(decision.IsAllowed);
        Assert.Equal(organizationId, reader.OrganizationId);
        Assert.Equal("member-a", reader.SubjectId);
    }

    [Theory]
    [InlineData(OrganizationAccessDecision.OrganizationNotFound)]
    [InlineData(OrganizationAccessDecision.OrganizationInactive)]
    [InlineData(OrganizationAccessDecision.MembershipNotFound)]
    [InlineData(OrganizationAccessDecision.MembershipInactive)]
    public async Task Unavailable_user_membership_is_denied_without_leaking_state(
        OrganizationAccessDecision accessDecision)
    {
        ITenantEndpointAccessPolicy policy = CreatePolicy(
            AccessSubject.User("member-a"), new RecordingAccessReader(accessDecision));

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(), Guid.NewGuid().ToString("D"), CancellationToken.None);

        Assert.False(decision.IsAllowed);
        Assert.Equal(StatusCodes.Status403Forbidden, decision.StatusCode);
        Assert.Equal(OrganizationTenancyErrors.AccessDeniedCode, decision.ErrorCode);
    }

    [Theory]
    [InlineData(AccessSubjectKind.AdminActor)]
    [InlineData(AccessSubjectKind.Service)]
    [InlineData(AccessSubjectKind.System)]
    public async Task Trusted_non_user_subject_kinds_bypass_membership_lookup(AccessSubjectKind subjectKind)
    {
        RecordingAccessReader reader = new(OrganizationAccessDecision.OrganizationNotFound);
        ITenantEndpointAccessPolicy policy = CreatePolicy(new AccessSubject(subjectKind, "trusted-a"), reader);

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(), "non-organization-scope", CancellationToken.None);

        Assert.True(decision.IsAllowed);
        Assert.Equal(0, reader.CallCount);
    }

    [Fact]
    public async Task Missing_subject_is_unauthenticated()
    {
        ITenantEndpointAccessPolicy policy = CreatePolicy(
            null, new RecordingAccessReader(OrganizationAccessDecision.Allowed));

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(), Guid.NewGuid().ToString("D"), CancellationToken.None);

        Assert.False(decision.IsAllowed);
        Assert.Equal(StatusCodes.Status401Unauthorized, decision.StatusCode);
        Assert.Equal(OrganizationTenancyErrors.UnauthenticatedCode, decision.ErrorCode);
    }

    [Fact]
    public void Registration_rejects_null_services()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Gma.Extensions.Organizations.Tenancy.DependencyInjection
                .AddOrganizationsTenancyExtension(null!));
    }

    private static ITenantEndpointAccessPolicy CreatePolicy(
        AccessSubject? subject,
        IOrganizationAccessDecisionReader reader)
    {
        ServiceCollection services = new();
        services.AddSingleton<IAccessHttpSubjectResolver>(new StubSubjectResolver(subject));
        services.AddSingleton(reader);
        services.AddOrganizationsTenancyExtension();
        return services.BuildServiceProvider().GetRequiredService<ITenantEndpointAccessPolicy>();
    }

    private sealed class StubSubjectResolver(AccessSubject? subject) : IAccessHttpSubjectResolver
    {
        public AccessSubject? ResolveSubject(HttpContext httpContext) => subject;
    }

    private sealed class RecordingAccessReader(OrganizationAccessDecision decision)
        : IOrganizationAccessDecisionReader
    {
        public int CallCount { get; private set; }
        public Guid? OrganizationId { get; private set; }
        public string? SubjectId { get; private set; }

        public Task<OrganizationAccessDecision> ReadAsync(
            Guid organizationId,
            string subjectId,
            CancellationToken cancellationToken)
        {
            this.CallCount++;
            this.OrganizationId = organizationId;
            this.SubjectId = subjectId;
            return Task.FromResult(decision);
        }
    }
}
