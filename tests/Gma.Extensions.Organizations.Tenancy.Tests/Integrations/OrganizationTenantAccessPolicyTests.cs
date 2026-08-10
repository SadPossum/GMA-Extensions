namespace Gma.Extensions.Organizations.Tenancy.Tests;

using Gma.Extensions.Organizations.Tenancy;
using Gma.Framework.AccessControl;
using Gma.Framework.AccessControl.AspNetCore;
using Gma.Framework.Api.Tenancy;
using Gma.Modules.Organizations.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
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
    public async Task Missing_or_inactive_access_is_denied_without_leaking_state(
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
    [InlineData(OrganizationAccessDecision.Unknown)]
    [InlineData(OrganizationAccessDecision.Unavailable)]
    [InlineData((OrganizationAccessDecision)999)]
    public async Task Indeterminate_access_is_reported_as_unavailable(
        OrganizationAccessDecision accessDecision)
    {
        ITenantEndpointAccessPolicy policy = CreatePolicy(
            AccessSubject.User("member-a"),
            new RecordingAccessReader(accessDecision));

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(),
            Guid.NewGuid().ToString("D"),
            CancellationToken.None);

        Assert.False(decision.IsAllowed);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, decision.StatusCode);
        Assert.Equal(OrganizationTenancyErrors.AccessUnavailableCode, decision.ErrorCode);
        Assert.Equal(OrganizationTenancyErrors.AccessUnavailableMessage, decision.ErrorMessage);
    }

    [Fact]
    public async Task Reader_failure_is_reported_as_unavailable()
    {
        ITenantEndpointAccessPolicy policy = CreatePolicy(
            AccessSubject.User("member-a"),
            new ThrowingAccessReader(new InvalidOperationException("reader unavailable")));

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(),
            Guid.NewGuid().ToString("D"),
            CancellationToken.None);

        Assert.False(decision.IsAllowed);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, decision.StatusCode);
        Assert.Equal(OrganizationTenancyErrors.AccessUnavailableCode, decision.ErrorCode);
    }

    [Fact]
    public async Task Caller_requested_cancellation_propagates()
    {
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        ITenantEndpointAccessPolicy policy = CreatePolicy(
            AccessSubject.User("member-a"),
            new ThrowingAccessReader(new OperationCanceledException(cancellation.Token)));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => policy
            .AuthorizeAsync(
                new DefaultHttpContext(),
                Guid.NewGuid().ToString("D"),
                cancellation.Token)
            .AsTask());
    }

    [Fact]
    public async Task Provider_cancellation_without_caller_cancellation_is_unavailable()
    {
        ITenantEndpointAccessPolicy policy = CreatePolicy(
            AccessSubject.User("member-a"),
            new ThrowingAccessReader(new OperationCanceledException()));

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(),
            Guid.NewGuid().ToString("D"),
            CancellationToken.None);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, decision.StatusCode);
        Assert.Equal(OrganizationTenancyErrors.AccessUnavailableCode, decision.ErrorCode);
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

    [Fact]
    public async Task Registration_does_not_require_logging_services()
    {
        ITenantEndpointAccessPolicy policy = CreatePolicy(
            AccessSubject.User("member-a"),
            new RecordingAccessReader(OrganizationAccessDecision.Allowed),
            registerLogger: false);

        TenantEndpointAccessDecision decision = await policy.AuthorizeAsync(
            new DefaultHttpContext(),
            Guid.NewGuid().ToString("D"),
            CancellationToken.None);

        Assert.True(decision.IsAllowed);
    }

    private static ITenantEndpointAccessPolicy CreatePolicy(
        AccessSubject? subject,
        IOrganizationAccessDecisionReader reader,
        bool registerLogger = true)
    {
        ServiceCollection services = new();
        services.AddSingleton<IAccessHttpSubjectResolver>(new StubSubjectResolver(subject));
        services.AddSingleton(reader);
        if (registerLogger)
        {
            services.AddSingleton<ILogger<OrganizationTenantAccessPolicy>>(
                NullLogger<OrganizationTenantAccessPolicy>.Instance);
        }

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

    private sealed class ThrowingAccessReader(Exception exception)
        : IOrganizationAccessDecisionReader
    {
        public Task<OrganizationAccessDecision> ReadAsync(
            Guid organizationId,
            string subjectId,
            CancellationToken cancellationToken) =>
            Task.FromException<OrganizationAccessDecision>(exception);
    }
}
