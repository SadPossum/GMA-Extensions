namespace Gma.Extensions.Organizations.AccessControl.Tests;

using Gma.Framework.AccessControl;
using Gma.Modules.AccessControl.Contracts;
using Gma.Modules.Organizations.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class OrganizationMembershipAccessProfileHandlerTests
{
    [Fact]
    public void Extension_references_only_module_contract_assemblies()
    {
        string[] moduleReferences = typeof(OrganizationMembershipAccessProfileHandler).Assembly
            .GetReferencedAssemblies()
            .Select(reference => reference.Name ?? string.Empty)
            .Where(name => name.StartsWith("Gma.Modules.", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "Gma.Modules.AccessControl.Contracts",
                "Gma.Modules.Organizations.Contracts"
            ],
            moduleReferences);
    }

    [Fact]
    public async Task Active_membership_does_not_revoke_profile_assignments()
    {
        RecordingRevoker revoker = new();
        OrganizationMembershipAccessProfileHandler handler = CreateHandler(revoker);

        await handler.HandleAsync(CreateEvent(OrganizationMembershipStatus.Active), CancellationToken.None);

        Assert.Empty(revoker.Calls);
    }

    [Theory]
    [InlineData(OrganizationMembershipStatus.Suspended)]
    [InlineData(OrganizationMembershipStatus.Removed)]
    public async Task Inactive_membership_revokes_exact_subject_scope_profile_assignments(
        OrganizationMembershipStatus status)
    {
        RecordingRevoker revoker = new();
        OrganizationMembershipAccessProfileHandler handler = CreateHandler(revoker);

        await handler.HandleAsync(CreateEvent(status), CancellationToken.None);

        RevocationCall call = Assert.Single(revoker.Calls);
        Assert.Equal(AccessSubject.User("user-a"), call.Subject);
        Assert.Equal(AccessScope.Parse("tenant:tenant-a"), call.OwnerScope);
        Assert.Equal(AccessSubject.System("membership-lifecycle"), call.Actor);
    }

    [Fact]
    public async Task Replayed_inactive_membership_event_delegates_idempotence_to_access_control()
    {
        RecordingRevoker revoker = new();
        OrganizationMembershipAccessProfileHandler handler = CreateHandler(revoker);
        OrganizationMembershipChangedIntegrationEvent integrationEvent = CreateEvent(
            OrganizationMembershipStatus.Removed);

        await handler.HandleAsync(integrationEvent, CancellationToken.None);
        await handler.HandleAsync(integrationEvent, CancellationToken.None);

        Assert.Equal(2, revoker.Calls.Count);
    }

    [Fact]
    public async Task Inactive_membership_forwards_cancellation_to_access_control()
    {
        RecordingRevoker revoker = new();
        OrganizationMembershipAccessProfileHandler handler = CreateHandler(revoker);
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await handler.HandleAsync(
            CreateEvent(OrganizationMembershipStatus.Suspended),
            cancellation.Token);

        Assert.Equal(cancellation.Token, Assert.Single(revoker.Calls).CancellationToken);
    }

    [Fact]
    public void Registration_rejects_null_services()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Gma.Extensions.Organizations.AccessControl.DependencyInjection
                .AddOrganizationsAccessControlExtension(null!));
    }

    [Theory]
    [InlineData("Invalid Scope", "membership-lifecycle")]
    [InlineData("tenant", " ")]
    public void Registration_options_fail_closed_for_invalid_scope_or_actor(
        string ownerScopeSegmentName,
        string systemActorId)
    {
        ServiceCollection services = new();
        services.AddOrganizationsAccessControlExtension(options =>
        {
            options.OwnerScopeSegmentName = ownerScopeSegmentName;
            options.SystemActorId = systemActorId;
        });
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<OrganizationsAccessControlOptions>>().Value);
    }

    private static OrganizationMembershipAccessProfileHandler CreateHandler(RecordingRevoker revoker) =>
        new(
            revoker,
            Options.Create(new OrganizationsAccessControlOptions
            {
                OwnerScopeSegmentName = "tenant",
                SystemActorId = "membership-lifecycle"
            }));

    private static OrganizationMembershipChangedIntegrationEvent CreateEvent(
        OrganizationMembershipStatus status) =>
        new(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            "tenant-a",
            Guid.NewGuid(),
            Guid.NewGuid(),
            "user-a",
            status == OrganizationMembershipStatus.Active
                ? OrganizationMembershipChange.Joined
                : OrganizationMembershipChange.Suspended,
            OrganizationMembershipRole.Member,
            status,
            2);

    private sealed class RecordingRevoker : IAccessProfileAssignmentRevoker
    {
        public List<RevocationCall> Calls { get; } = [];

        public Task<int> RevokeAllAsync(
            AccessSubject subject,
            AccessScope ownerScope,
            AccessSubject actor,
            CancellationToken cancellationToken)
        {
            this.Calls.Add(new RevocationCall(subject, ownerScope, actor, cancellationToken));
            return Task.FromResult(0);
        }
    }

    private sealed record RevocationCall(
        AccessSubject Subject,
        AccessScope OwnerScope,
        AccessSubject Actor,
        CancellationToken CancellationToken);
}
